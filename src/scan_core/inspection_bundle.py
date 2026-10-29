"""Create and verify deterministic portable Scan Inspection Bundle v1 archives."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import stat
import zipfile
from typing import Any, Mapping

from .handoff import build_handoff, canonical_handoff_json
from .state import canonical_state_json, state_digest
from .validate import validate_state

INSPECTION_BUNDLE_VERSION = "1"
MANIFEST_NAME = "manifest.json"
STATE_NAME = "state.json"
HANDOFF_NAME = "handoff.json"
MEMBER_ORDER = (MANIFEST_NAME, STATE_NAME, HANDOFF_NAME)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
REGULAR_FILE_MODE = 0o100644
MAX_MANIFEST_BYTES = 1_000_000
MAX_STATE_BYTES = 128_000_000
MAX_HANDOFF_BYTES = 5_000_000
MAX_BUNDLE_BYTES = 140_000_000


@dataclass(frozen=True)
class InspectionBundleResult:
    path: Path
    bundle_digest: str
    state_digest: str
    handoff_digest: str
    size_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "bundle_digest": self.bundle_digest,
            "state_digest": self.state_digest,
            "handoff_digest": self.handoff_digest,
            "size_bytes": self.size_bytes,
        }


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _member_record(data: bytes, media_type: str) -> dict[str, Any]:
    return {"sha256": _sha256(data), "size_bytes": len(data), "media_type": media_type}


def _manifest(state: Mapping[str, Any], handoff: Mapping[str, Any], state_bytes: bytes, handoff_bytes: bytes) -> dict[str, Any]:
    coverage = state.get("coverage", {})
    summary = state.get("summary", {})
    return {
        "inspection_bundle_version": INSPECTION_BUNDLE_VERSION,
        "identity": {
            "schema_version": state.get("schema_version"),
            "state_digest": state_digest(state),
            "snapshot_digest": state.get("provenance", {}).get("snapshot_digest"),
            "scan_id": state.get("run", {}).get("scan_id"),
            "scan_version": state.get("run", {}).get("scan_version"),
            "scan_mode": state.get("run", {}).get("scan_mode"),
            "handoff_digest": handoff.get("handoff_digest"),
        },
        "members": {
            STATE_NAME: _member_record(state_bytes, "application/json"),
            HANDOFF_NAME: _member_record(handoff_bytes, "application/json"),
        },
        "coverage": {
            "discovery_complete": coverage.get("discovery_complete"),
            "analysis_complete": coverage.get("analysis_complete"),
            "checks_complete": coverage.get("checks_complete"),
            "discovered_artifact_count": coverage.get("discovered_artifact_count"),
            "counts_by_status": coverage.get("counts_by_status", {}),
            "counts_by_check_status": coverage.get("counts_by_check_status", {}),
        },
        "summary": {
            "readiness": summary.get("readiness"),
            "finding_count": len(state.get("findings", [])),
            "control_count": len(state.get("controls", [])),
            "unknown_count": len(state.get("unknowns", [])),
            "check_count": len(state.get("checks", [])),
        },
        "contract": {
            "authoritative_member": STATE_NAME,
            "handoff_is_projection": True,
            "manifest_self_digest_embedded": False,
            "may_contain_redacted_target_derived_semantic_text": True,
            "contains_executable_plugin_payloads": False,
            "no_blended_quality_score": True,
        },
    }


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename=name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = REGULAR_FILE_MODE << 16
    info.internal_attr = 0
    info.flag_bits = 0
    return info


def _write_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    archive.writestr(_zip_info(name), data)


def create_inspection_bundle(state: Mapping[str, Any], output: Path) -> InspectionBundleResult:
    """Create a deterministic v1 bundle from one validated canonical Scan state."""
    validate_state(state)
    handoff = build_handoff(state)
    state_bytes = (canonical_state_json(state) + "\n").encode("utf-8")
    handoff_bytes = (canonical_handoff_json(handoff) + "\n").encode("utf-8")
    if len(state_bytes) > MAX_STATE_BYTES:
        raise ValueError(f"canonical state exceeds bundle member limit ({MAX_STATE_BYTES} bytes)")
    if len(handoff_bytes) > MAX_HANDOFF_BYTES:
        raise ValueError(f"canonical handoff exceeds bundle member limit ({MAX_HANDOFF_BYTES} bytes)")
    manifest = _manifest(state, handoff, state_bytes, handoff_bytes)
    manifest_bytes = _canonical_json_bytes(manifest)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ValueError(f"bundle manifest exceeds member limit ({MAX_MANIFEST_BYTES} bytes)")

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        _write_member(archive, MANIFEST_NAME, manifest_bytes)
        _write_member(archive, STATE_NAME, state_bytes)
        _write_member(archive, HANDOFF_NAME, handoff_bytes)
    size = output.stat().st_size
    if size > MAX_BUNDLE_BYTES:
        output.unlink(missing_ok=True)
        raise ValueError(f"Inspection Bundle exceeds archive limit ({MAX_BUNDLE_BYTES} bytes)")
    bundle_bytes = output.read_bytes()
    return InspectionBundleResult(
        path=output,
        bundle_digest=_sha256(bundle_bytes),
        state_digest=str(manifest["identity"]["state_digest"]),
        handoff_digest=str(manifest["identity"]["handoff_digest"]),
        size_bytes=len(bundle_bytes),
    )


def _load_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Cannot parse {label}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return value


def _read_members(path: Path) -> tuple[dict[str, bytes], bytes]:
    if path.is_symlink():
        raise ValueError("Inspection Bundle path must not be a symlink")
    size = path.stat().st_size
    if size > MAX_BUNDLE_BYTES:
        raise ValueError(f"Inspection Bundle exceeds archive limit ({MAX_BUNDLE_BYTES} bytes)")
    bundle_bytes = path.read_bytes()
    try:
        archive = zipfile.ZipFile(path, mode="r")
    except zipfile.BadZipFile as error:
        raise ValueError(f"Invalid Inspection Bundle ZIP: {error}") from error
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError("Inspection Bundle contains duplicate member names")
        if tuple(names) != MEMBER_ORDER:
            raise ValueError(f"Inspection Bundle members/order must be exactly {MEMBER_ORDER}")
        limits = {MANIFEST_NAME: MAX_MANIFEST_BYTES, STATE_NAME: MAX_STATE_BYTES, HANDOFF_NAME: MAX_HANDOFF_BYTES}
        members: dict[str, bytes] = {}
        for info in infos:
            if info.date_time != FIXED_ZIP_TIME:
                raise ValueError(f"Inspection Bundle member {info.filename} has noncanonical timestamp metadata")
            if info.compress_type != zipfile.ZIP_STORED or info.compress_size != info.file_size:
                raise ValueError(f"Inspection Bundle member {info.filename} must be stored without compression")
            if info.flag_bits & 0x1:
                raise ValueError(f"Inspection Bundle member {info.filename} must not be encrypted")
            if info.create_system != 3:
                raise ValueError(f"Inspection Bundle member {info.filename} must use canonical Unix ZIP metadata")
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode != REGULAR_FILE_MODE or not stat.S_ISREG(mode):
                raise ValueError(f"Inspection Bundle member {info.filename} must be a canonical regular file")
            if info.file_size > limits[info.filename]:
                raise ValueError(f"Inspection Bundle member {info.filename} exceeds its byte limit")
            data = archive.read(info)
            if len(data) != info.file_size:
                raise ValueError(f"Inspection Bundle member {info.filename} size changed while reading")
            members[info.filename] = data
    return members, bundle_bytes


def verify_inspection_bundle(path: Path) -> dict[str, Any]:
    """Verify a v1 bundle from archive metadata through canonical state/handoff identity."""
    members, bundle_bytes = _read_members(path)
    manifest = _load_json(members[MANIFEST_NAME], "manifest.json")
    if manifest.get("inspection_bundle_version") != INSPECTION_BUNDLE_VERSION:
        raise ValueError(f"inspection_bundle_version must be {INSPECTION_BUNDLE_VERSION}")
    if members[MANIFEST_NAME] != _canonical_json_bytes(manifest):
        raise ValueError("manifest.json is not in canonical v1 JSON encoding")

    member_contract = manifest.get("members")
    if not isinstance(member_contract, Mapping) or set(member_contract) != {STATE_NAME, HANDOFF_NAME}:
        raise ValueError("manifest members must describe exactly state.json and handoff.json")
    for name in (STATE_NAME, HANDOFF_NAME):
        row = member_contract[name]
        if not isinstance(row, Mapping):
            raise ValueError(f"manifest member record for {name} must be an object")
        actual = members[name]
        if row.get("sha256") != _sha256(actual) or row.get("size_bytes") != len(actual):
            raise ValueError(f"manifest digest/size does not match {name}")

    state = _load_json(members[STATE_NAME], STATE_NAME)
    validate_state(state)
    canonical_state_bytes = (canonical_state_json(state) + "\n").encode("utf-8")
    if members[STATE_NAME] != canonical_state_bytes:
        raise ValueError("state.json is not the canonical Scan state encoding")
    actual_state_digest = state_digest(state)

    handoff = _load_json(members[HANDOFF_NAME], HANDOFF_NAME)
    canonical_handoff_bytes = (canonical_handoff_json(handoff) + "\n").encode("utf-8")
    if members[HANDOFF_NAME] != canonical_handoff_bytes:
        raise ValueError("handoff.json is not the canonical handoff encoding")
    rebuilt_handoff = build_handoff(state)
    rebuilt_handoff_bytes = (canonical_handoff_json(rebuilt_handoff) + "\n").encode("utf-8")
    if members[HANDOFF_NAME] != rebuilt_handoff_bytes:
        raise ValueError("handoff.json does not exactly match the default handoff rebuilt from state.json")

    identity = manifest.get("identity")
    if not isinstance(identity, Mapping):
        raise ValueError("manifest identity must be an object")
    expected_identity = {
        "schema_version": state.get("schema_version"),
        "state_digest": actual_state_digest,
        "snapshot_digest": state.get("provenance", {}).get("snapshot_digest"),
        "scan_id": state.get("run", {}).get("scan_id"),
        "scan_version": state.get("run", {}).get("scan_version"),
        "scan_mode": state.get("run", {}).get("scan_mode"),
        "handoff_digest": rebuilt_handoff.get("handoff_digest"),
    }
    if dict(identity) != expected_identity:
        raise ValueError("manifest identity does not match bundled canonical state/handoff")

    expected_manifest = _manifest(state, rebuilt_handoff, members[STATE_NAME], members[HANDOFF_NAME])
    if manifest != expected_manifest:
        raise ValueError("manifest contents do not match canonical bundle metadata derived from state.json")
    contract = manifest.get("contract", {})
    if contract.get("no_blended_quality_score") is not True:
        raise ValueError("Inspection Bundle contract must preserve no_blended_quality_score=true")

    return {
        "inspection_bundle_version": INSPECTION_BUNDLE_VERSION,
        "bundle_digest": _sha256(bundle_bytes),
        "size_bytes": len(bundle_bytes),
        "state_digest": actual_state_digest,
        "snapshot_digest": expected_identity["snapshot_digest"],
        "handoff_digest": expected_identity["handoff_digest"],
        "schema_version": expected_identity["schema_version"],
        "scan_id": expected_identity["scan_id"],
        "coverage": manifest["coverage"],
        "summary": manifest["summary"],
        "verified": True,
        "target_executed": False,
        "network_used": False,
        "no_blended_quality_score": True,
    }


def format_bundle_verification(value: Mapping[str, Any]) -> str:
    return "\n".join([
        f"Inspection Bundle v{value['inspection_bundle_version']}: verified",
        f"Bundle: {value['bundle_digest']}",
        f"State: {value['state_digest']}",
        f"Snapshot: {value['snapshot_digest']}",
        f"Handoff: {value['handoff_digest']}",
        f"Readiness: {value['summary'].get('readiness')}",
        "No target execution or network access was used for verification.",
    ])
