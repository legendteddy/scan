"""Public Scan Core API.

Slice 1 freezes packaging, configuration, validation dispatch and CLI exit codes.
Inventory, rendering and privacy execution land in later v0.2 slices.
"""

from .config import ScanConfig, ScanResult
from .validate import validate_path, validate_report, validate_state

__version__ = "0.2.0.dev1"

__all__ = [
    "ScanConfig",
    "ScanResult",
    "validate_path",
    "validate_report",
    "validate_state",
    "__version__",
]
