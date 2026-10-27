"""Public Scan Core API.

Slice 1 freezes packaging, configuration, validation dispatch and CLI exit codes.
Slice 2 adds deterministic inventory and snapshot identity.
Slice 3 adds canonical Scan 1.3 state construction and state-only scan orchestration.
Rendering and privacy execution land in later v0.2 slices.
"""

from .config import ScanConfig, ScanResult
from .core import scan_project
from .inventory import InventoryArtifact, InventoryResult, build_inventory
from .snapshot import Snapshot, build_snapshot, canonical_manifest
from .state import build_state, canonical_state_json, configuration_digest
from .validate import validate_path, validate_report, validate_state
from .version import __version__

__all__ = [
    "InventoryArtifact",
    "InventoryResult",
    "ScanConfig",
    "ScanResult",
    "Snapshot",
    "build_inventory",
    "build_snapshot",
    "build_state",
    "canonical_manifest",
    "canonical_state_json",
    "configuration_digest",
    "scan_project",
    "validate_path",
    "validate_report",
    "validate_state",
    "__version__",
]
