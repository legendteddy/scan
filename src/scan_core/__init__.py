"""Public Scan Core API.

Slice 1 freezes packaging, configuration, validation dispatch and CLI exit codes.
Slice 2 adds deterministic inventory and snapshot identity.
Slice 3 adds canonical Scan 1.3 state construction and state-only scan orchestration.
Slice 4 adds deterministic privacy assessment, redaction and egress previews.
Slice 5 renders validated self-contained HTML directly from canonical state.
Slice 6 adds ScanBench v1, bundled schemas, project config and release hardening.
"""

from .builder import (
    ActionRecord,
    BuilderError,
    CheckRecord,
    ComponentRecord,
    ControlRecord,
    EvidenceRecord,
    FindingRecord,
    RelationshipRecord,
    SemanticStateBuilder,
    UnknownRecord,
    upgrade_semantic_state,
)
from .compare import Comparison, compare_states
from .config import ScanConfig, ScanResult
from .core import scan_project
from .inventory import InventoryArtifact, InventoryResult, build_inventory
from .privacy import (
    EgressPreview,
    PrivacyAssessment,
    RedactionPolicy,
    RedactionResult,
    assess_privacy,
    build_egress_preview,
    prepare_text_for_egress,
    redact_value,
)
from .render import render_html, render_report
from .scanbench import BenchResult, run_bench
from .schema import schema_object, schema_text
from .settings import ProjectSettings, load_project_settings
from .snapshot import Snapshot, build_snapshot, canonical_manifest
from .state import build_state, canonical_state_json, configuration_digest, state_digest
from .validate import validate_path, validate_report, validate_state
from .version import __version__

__all__ = [
    "ActionRecord",
    "BenchResult",
    "BuilderError",
    "CheckRecord",
    "ComponentRecord",
    "ControlRecord",
    "Comparison",
    "EgressPreview",
    "EvidenceRecord",
    "FindingRecord",
    "InventoryArtifact",
    "InventoryResult",
    "PrivacyAssessment",
    "ProjectSettings",
    "RedactionPolicy",
    "RedactionResult",
    "ScanConfig",
    "ScanResult",
    "SemanticStateBuilder",
    "Snapshot",
    "RelationshipRecord",
    "UnknownRecord",
    "assess_privacy",
    "build_egress_preview",
    "build_inventory",
    "build_snapshot",
    "build_state",
    "canonical_manifest",
    "canonical_state_json",
    "compare_states",
    "configuration_digest",
    "load_project_settings",
    "prepare_text_for_egress",
    "redact_value",
    "render_html",
    "render_report",
    "run_bench",
    "scan_project",
    "schema_object",
    "schema_text",
    "state_digest",
    "upgrade_semantic_state",
    "validate_path",
    "validate_report",
    "validate_state",
    "__version__",
]
