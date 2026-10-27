"""Public Scan Core API.

The v0.2 line established deterministic inventory, canonical state, privacy,
self-contained rendering and ScanBench. The v0.3 line adds repeat-scan state
comparison, local baselines, strict evidence freshness/reuse semantics and local Git change context.
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
from .reuse import ReuseDecision, ReusePolicy, evaluate_reuse
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
    "ReuseDecision",
    "ReusePolicy",
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
    "evaluate_reuse",
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
