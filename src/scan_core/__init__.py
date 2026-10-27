"""Public Scan Core API.

Slice 1 freezes packaging, configuration, validation dispatch and CLI exit codes.
Slice 2 adds deterministic inventory and snapshot identity; rendering and privacy
execution land in later v0.2 slices.
"""

from .config import ScanConfig, ScanResult
from .inventory import InventoryArtifact, InventoryResult, build_inventory
from .snapshot import Snapshot, build_snapshot, canonical_manifest
from .validate import validate_path, validate_report, validate_state

__version__ = "0.2.0.dev2"

__all__ = [
    "InventoryArtifact",
    "InventoryResult",
    "ScanConfig",
    "ScanResult",
    "Snapshot",
    "build_inventory",
    "build_snapshot",
    "canonical_manifest",
    "validate_path",
    "validate_report",
    "validate_state",
    "__version__",
]
