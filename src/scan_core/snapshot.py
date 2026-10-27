"""Canonical manifest serialization and deterministic snapshot identity."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .inventory import InventoryArtifact, InventoryResult


@dataclass(frozen=True)
class Snapshot:
    digest: str
    artifact_count: int
    manifest_json: str
    identity_complete: bool


def _manifest_row(artifact: InventoryArtifact) -> dict[str, Any]:
    return {
        "locator": artifact.locator,
        "path_kind": artifact.path_kind,
        "size_bytes": artifact.size_bytes,
        "content_identity": artifact.content_identity,
        "symlink_target_identity": (
            artifact.content_identity if artifact.path_kind == "symlink" else None
        ),
        "symlink_scope": artifact.symlink_scope,
        "excluded": artifact.excluded,
    }


def canonical_manifest(inventory: InventoryResult) -> str:
    rows = [_manifest_row(item) for item in sorted(inventory.artifacts, key=lambda item: item.locator)]
    return json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_snapshot(inventory: InventoryResult) -> Snapshot:
    manifest = canonical_manifest(inventory)
    digest = "sha256:" + hashlib.sha256(manifest.encode("utf-8", errors="surrogatepass")).hexdigest()
    return Snapshot(
        digest=digest,
        artifact_count=len(inventory.artifacts),
        manifest_json=manifest,
        identity_complete=inventory.identity_complete,
    )
