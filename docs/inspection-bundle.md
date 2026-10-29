# Scan Inspection Bundle v1

Inspection Bundle v1 is Scan’s portable machine-to-machine artifact for one exact inspection snapshot. It packages the canonical validated Scan state and the deterministic default handoff under a small verified manifest.

The bundle is intentionally not an executable plugin container. It contains exactly three stored ZIP members in deterministic order:

1. `manifest.json`
2. `state.json`
3. `handoff.json`

No arbitrary attachments are permitted in v1.

## Create

```bash
scan-bundle create .scan/state.json --output inspection.scanbundle --json
```

Creation validates the source state, derives the default bounded handoff from that exact state, canonicalizes both JSON members, and writes a deterministic `ZIP_STORED` archive with fixed timestamps and regular-file metadata.

Repeated creation from the same state on the same implementation/runtime is expected to be byte-identical. The command reports the SHA-256 digest of the complete bundle bytes.

## Verify

```bash
scan-bundle verify inspection.scanbundle --json
```

Verification performs no target execution and no network access. It checks:

- archive byte-size limit before member reads;
- exactly the three v1 member names, in canonical order;
- no duplicate, unexpected or path-traversal members;
- fixed timestamps, stored/no-compression method, canonical Unix regular-file mode, and no encryption;
- per-member byte-size ceilings;
- canonical JSON encoding;
- `state.json` validates as a Scan state and has the manifest’s exact state/snapshot/run identity;
- `manifest.json` member SHA-256 and sizes match `state.json` and `handoff.json`;
- the default handoff rebuilt from bundled `state.json` is byte-for-byte identical to bundled `handoff.json`;
- all manifest coverage/count/readiness metadata exactly matches values derived from the bundled state;
- `no_blended_quality_score` remains true.

A modified handoff cannot become trusted merely by updating its member digest in the manifest: verification rebuilds the handoff from the authoritative state and requires exact equality.

## Identity and authority

`state.json` is the authoritative member. `handoff.json` is the bounded agent-facing projection described in `docs/inspection-handoff.md`.

The manifest binds:

- Scan state schema version;
- canonical state digest;
- snapshot digest;
- scan ID/version/mode;
- handoff digest;
- separate finding/control/unknown/check counts;
- coverage completion fields and status counters;
- readiness text.

The manifest has no overall health/trust score.

## Size and archive safety

v1 limits are intentionally simple:

- manifest: 1 MB;
- canonical state: 128 MB;
- handoff: 5 MB;
- complete archive: 140 MB.

Members are stored without compression, so verification does not need to expand attacker-controlled compressed data. ZIP64 is disabled during creation.

## Privacy boundary

The bundle does **not** promise zero target-derived text. Canonical Scan state may contain semantic findings/evidence text that has already passed Scan’s configured redaction policy. The manifest therefore states `may_contain_redacted_target_derived_semantic_text: true`.

The bundle does not add project source bytes or executable payloads beyond whatever semantic data is already present in the canonical state contract. Before sharing a bundle outside its original trust boundary, apply the same privacy judgment you would apply to the underlying Scan state/report.

## Human report relationship

Inspection Bundle v1 does not embed the self-contained HTML report. The existing report remains the human-facing artifact; the bundle is the stable portable state/handoff artifact for agents and tools. A later format version may add explicitly typed optional members only if their provenance and verification semantics remain equally strict.
