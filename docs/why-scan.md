# Why Scan exists

AI-assisted review has a recurring failure mode: **the conclusion can sound more complete than the inspection actually was**. Scan exists to make that gap inspectable.

## A false-confidence example

Imagine a repository containing 280 discoverable artifacts. An agent reads 12 source files, notices a test directory and a deployment workflow, then reports:

> "I reviewed the whole project. The architecture looks sound, tests are present, and I found no release blockers."

That statement may be fluent, but the evidence does not establish it. From the description alone, a reviewer cannot tell:

- whether all 280 artifacts were even discovered;
- which 12 files were actually read;
- whether the remaining files were generated, unreadable, ignored or simply skipped;
- whether the tests were executed or merely observed as files;
- whether runtime, deployment or external-service behavior was verified;
- whether an earlier observation was reused and how old it was;
- what the agent could not determine.

This is a **fictional demonstration**, not a measurement of any particular model or agent. The problem is the missing inspection record, not the wording style.

## What Scan changes

For the same situation, a Scan-backed review is expected to separate claims such as:

```text
Artifacts discovered:       280
Artifacts semantically read: 12
Metadata-only / unassessed: 268
Tests observed:              yes
Tests executed:              no
Runtime verification:        not performed
Unknowns:                    explicitly recorded
```

If a second scan reuses valid evidence for an unchanged file, that evidence remains marked as reuse with its original depth and observation time. If Git reports a file as changed, that is prioritization context, not proof that everything else was inspected. If a finding disappears between two states, Scan calls it resolved in the **state-delta** sense only; that is not automatically proof of a runtime fix.

The important change is not that Scan produces a stronger verdict. It produces a **more falsifiable account of how the verdict was reached**.

## What Scan still does not prove

A complete inventory does not prove semantic correctness. Static inspection does not prove runtime behavior. A passing structural validator does not prove that a finding is factually true. A clean delta does not prove an unchanged external service, permission or dependency is safe.

Scan's role is to keep those boundaries visible and portable so a human or another agent can continue from evidence rather than from an unsupported headline.
