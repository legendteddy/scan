# Explicit semantic continuation

Scan Core never treats a producer listed in a baseline as authorized for the
current run. Ordinary CLI scans still register only current Core/Git tools. An
authorized semantic agent can use the Python API to register its current producer
and check definitions before the ordinary scan evaluates a baseline:

```python
from pathlib import Path
from scan_core import (
    ScanConfig, SemanticCheckDefinition, SemanticRegistration,
    SemanticStateBuilder, canonical_state_json, scan_project,
)

root = Path("project").resolve()
config = ScanConfig(root=root, output_state=root / ".scan/state.json")

# Define these from the CURRENT invocation's check plan, not from prior state.
check = SemanticCheckDefinition(
    id="check:agent-logic", category="correctness_and_integrity",
    title="Application logic", scope="app.py", method="static source review",
)
registration = SemanticRegistration(
    producer_kind="local-model", producer_name="review-agent", producer_version="1",
    checks=(check,),
)
# check.digest is the current sha256 digest of ID/category/title/scope/method.

first = scan_project(config).state
builder = SemanticStateBuilder(first)
builder.add_check(
    record_id=check.id, category=check.category, title=check.title,
    scope=check.scope, method=check.method, status="not_assessed",
    artifact_ids=[], evidence_ids=[], verification_state="unverified",
    result="Not yet assessed", limitations="Runtime unverified",
    reason="Current semantic check plan", next_step="Inspect app.py",
)
artifact = next(row for row in first["artifacts"] if row["locator"] == "app.py")
# Perform the authorized static inspection here. Supply actual observations,
# limitations, locators and observation time; never invent an assessment.
# evidence_id = builder.add_evidence(
#     artifact_id=artifact["id"], locator="app.py:12", kind="static",
#     claim=actual_claim, result=actual_observation, method=check.method,
#     limitations=actual_limits, source_digest=artifact["content_identity"],
#     producer_kind="local-model", producer_name="review-agent", producer_version="1",
#     evidence_class="static_semantic", check_id=check.id,
# )
# builder.update_check(check.id, status="partial", evidence_ids=[evidence_id],
#                      artifact_ids=[artifact["id"]], verification_state="static",
#                      result=actual_result)
baseline = builder.build()
config.output_state.write_text(canonical_state_json(baseline), encoding="utf-8")

# A later invocation explicitly supplies its current plan/producer again.
second = scan_project(config, semantic_registrations=(registration,)).state
```

The example leaves observation fields commented because registration itself is
not analysis. The end-to-end regression in `tests/test_self_review_defects.py`
constructs actual synthetic semantic evidence and verifies successful reuse and
specific rejection reasons.

Each immutable `SemanticCheckDefinition` supplies a stable check ID and definition
whose current digest is computed locally. `SemanticRegistration` associates those
exact check IDs/digests with one producer kind/name/version. Checks from one
producer do not authorize another producer. Conflicting definitions and attempts
to impersonate built-in tools fail. Definitions should contain no secrets.
Registration is invocation-only: neither `.scan/config.toml` nor baseline JSON can
enable it. `extensions.semantic_continuation` records the current registrations;
`provenance.tool_versions` records available producers.

Reuse requires exact content identity, producer identity/version, check identity
and definition digest, eligible static evidence class and current privacy policy.
It preserves observation time, depth, method, limitations, source evidence ID and
immediate baseline state digest; reused evidence remains `verified_reuse`. Runtime,
live-service, deployment and time-sensitive evidence remain ineligible. Current
privacy redacts reused prose and rejects evidence for newly sensitive paths.

Registration creates unassessed current check rows. Reusing a receipt does not
mark checks assessed or artifacts analyzed, copy historical findings, or resolve
unknowns. Use fresh analysis and explicit builder updates for those judgments.
The baseline's rejected-reuse reason counts explain failed candidates.

Use `add_check(record_id=...)` to add a concrete check and
`update_check(existing_id, ...)` to update it. Multiple checks may share a category;
custom categories are allowed in addition to all required categories.
`category_coverage()` exposes required-category membership. Legacy
`assess_check(category=...)` updates the sole check in that category; it requires
an explicit `record_id` when multiple checks make the category ambiguous.

# Metadata authorization

Auxiliary reads share a boundary-safe reader. Parent/absolute ref traversal,
alternate streams, symlinks and Windows reparse points are rejected. Metadata
reads use pinned POSIX directory descriptors or verify the actual Windows file
handle path before reading bytes. Limits are: `.scan/config.toml` 64,000 bytes;
`.git` indirection, `HEAD`, loose refs and `commondir` 4,096 bytes each; Git config
1,000,000 bytes; packed refs 2,000,000 bytes. Oversized data is not partially
interpreted. Git config includes are never followed. No hooks, project code or
remote fetch are executed for provenance.

In-root `.git` file indirection works without expanding scope. External worktrees
require explicit grants for each exact metadata directory, for example:

```powershell
scan C:\work\project --git-metadata-root C:\repo\.git\worktrees\project --git-metadata-root C:\repo\.git
```

The equivalent API is `ScanConfig(git_metadata_roots=(Path(...), Path(...)))`.
The first grant permits bounded worktree HEAD/commondir reads; the second permits
bounded common refs/config reads. A parent grant does not authorize a child root.
External grants are reflected in the configuration digest and visible Git
limitations; they do not add external content to the authoritative inventory.
Internal metadata symlinks/reparse points are also rejected conservatively and
reported as unavailable. These options cannot be set by target configuration.

On Windows without symlink privileges, ScanBench explicitly reports when it uses
a native directory junction to exercise its escape fixture. File-symlink-specific
unit tests skip with the platform error; the separate junction tests still run.
