"""Deterministic privacy, redaction and egress-preview helpers for Scan Core."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
from pathlib import Path
import re
from typing import Any, Iterable, Literal, Mapping

from .config import RedactionLevel, ScanConfig
from .inventory import InventoryArtifact, InventoryResult


RedactionCategory = Literal["credential", "private-key", "email", "phone", "identifier"]


@dataclass(frozen=True)
class RedactionPolicy:
    level: RedactionLevel = "standard"
    sensitive_path_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class RedactionResult:
    value: str
    count: int
    categories: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return self.count > 0


@dataclass(frozen=True)
class ArtifactPrivacy:
    artifact_id: str
    locator: str
    safe_locator: str
    redaction_state: str
    redaction_count: int = 0
    categories: tuple[str, ...] = ()
    sensitive_path: bool = False
    egress_eligible: bool = False
    egress_bytes: int = 0
    omission_reason: str = ""


@dataclass(frozen=True)
class PrivacyAssessment:
    artifacts: tuple[ArtifactPrivacy, ...]
    redaction_count: int
    sensitive_path_count: int
    files_selected: int
    bytes_selected: int
    files_omitted_by_policy: int
    sensitive_paths_omitted: int
    warnings: tuple[str, ...] = ()

    def by_id(self) -> dict[str, ArtifactPrivacy]:
        return {item.artifact_id: item for item in self.artifacts}


@dataclass(frozen=True)
class EgressPreview:
    files_selected: int
    bytes_selected: int
    files_omitted_by_policy: int
    redaction_count: int
    sensitive_paths_omitted: int
    privacy_mode: str
    network_action: str = "none"

    def as_dict(self) -> dict[str, int | str]:
        return {
            "files_selected": self.files_selected,
            "bytes_selected": self.bytes_selected,
            "files_omitted_by_policy": self.files_omitted_by_policy,
            "redaction_count": self.redaction_count,
            "sensitive_paths_omitted": self.sensitive_paths_omitted,
            "privacy_mode": self.privacy_mode,
            "network_action": self.network_action,
        }


_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|sk-[A-Za-z0-9_-]{20,255})(?![A-Za-z0-9])"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?im)(?P<key>\b[A-Z0-9_.-]+\b)(?P<separator>\s*(?::|=)\s*)(?P<quote>['\"]?)(?P<value>[^\s'\"#,;}{\]\[]+)(?P=quote)"
)
_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.IGNORECASE)
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)")
_IDENTIFIER_ASSIGNMENT_RE = re.compile(
    r"(?im)(?P<prefix>\b(?:account(?:[_ -]?(?:number|no))?|acct(?:[_ -]?(?:number|no))?|iban|routing(?:[_ -]?(?:number|no))?|ssn|tax[_ -]?id|passport(?:[_ -]?(?:number|no))?)\b\s*(?::|=)\s*)(?P<quote>['\"]?)(?P<value>[A-Za-z0-9][A-Za-z0-9 ._-]{3,})(?P=quote)"
)


def _replace_simple(pattern: re.Pattern[str], text: str, label: str) -> tuple[str, int]:
    return pattern.subn(f"[REDACTED:{label}]", text)


def _replace_assignment(pattern: re.Pattern[str], text: str, label: str) -> tuple[str, int]:
    def replacement(match: re.Match[str]) -> str:
        return match.group("prefix") + f"[REDACTED:{label}]"

    return pattern.subn(replacement, text)


def _secret_assignment_key(key: str) -> bool:
    """Classify credential labels without treating token-like identifiers as secrets."""
    normalized = re.sub(r"[.-]+", "_", key.strip().lower())
    parts = [part for part in normalized.split("_") if part]
    joined = "_".join(parts)
    if any(part in {"password", "passwd", "pwd", "secret"} for part in parts):
        return True
    if joined in {"apikey", "accesskey", "privatekey"}:
        return True
    if any(
        pair in joined
        for pair in ("api_key", "access_key", "private_key")
    ):
        return True
    if "token" not in parts:
        return False
    token_context = {
        "api", "auth", "access", "refresh", "bearer", "github", "gitlab",
        "service", "credential", "secret", "key", "value", "session", "csrf", "id",
    }
    context = set(parts) - {"token"}
    return not context or bool(context & token_context)


def _replace_secret_assignments(text: str, label: str) -> tuple[str, int]:
    count = 0

    def replacement(match: re.Match[str]) -> str:
        nonlocal count
        if not _secret_assignment_key(match.group("key")):
            return match.group(0)
        count += 1
        return match.group("key") + match.group("separator") + f"[REDACTED:{label}]"

    return _SECRET_ASSIGNMENT_RE.sub(replacement, text), count


def redact_value(value: str, policy: RedactionPolicy) -> RedactionResult:
    """Redact deterministic sensitive patterns without retaining matched values."""
    if policy.level == "none":
        return RedactionResult(value=value, count=0, categories=())

    text = value
    count = 0
    categories: list[str] = []

    for pattern, label in (
        (_PRIVATE_KEY_RE, "private-key"),
        (_TOKEN_RE, "credential"),
    ):
        text, found = _replace_simple(pattern, text, label)
        if found:
            count += found
            categories.extend([label] * found)

    text, found = _replace_secret_assignments(text, "credential")
    if found:
        count += found
        categories.extend(["credential"] * found)

    if policy.level == "strict":
        for pattern, label, assignment in (
            (_EMAIL_RE, "email", False),
            (_PHONE_RE, "phone", False),
            (_IDENTIFIER_ASSIGNMENT_RE, "identifier", True),
        ):
            text, found = (
                _replace_assignment(pattern, text, label)
                if assignment
                else _replace_simple(pattern, text, label)
            )
            if found:
                count += found
                categories.extend([label] * found)

    return RedactionResult(value=text, count=count, categories=tuple(sorted(set(categories))))


def _normalized_pattern(pattern: str) -> str:
    return pattern.replace("\\", "/").strip()


def path_is_sensitive(locator: str, patterns: Iterable[str]) -> bool:
    for raw in patterns:
        pattern = _normalized_pattern(raw)
        if not pattern:
            continue
        if fnmatch.fnmatchcase(locator, pattern):
            return True
        if pattern.endswith("/**"):
            prefix = pattern[:-3].rstrip("/")
            if locator == prefix or locator.startswith(prefix + "/"):
                return True
    return False


def safe_locator(artifact_id: str) -> str:
    suffix = artifact_id.split(":", 1)[-1][:20]
    return f"[REDACTED:path]/{suffix}"


def _read_text_bounded(path: Path, max_bytes: int) -> tuple[str | None, str]:
    """Read bounded text as untrusted data; never execute or import it."""
    if max_bytes < 0:
        return None, "invalid byte limit"
    try:
        with path.open("rb") as stream:
            data = stream.read(max_bytes + 1)
    except OSError as error:
        return None, f"unreadable:{error.__class__.__name__}"
    if len(data) > max_bytes:
        return None, "content exceeds configured privacy-read limit"
    if b"\x00" in data:
        return None, "binary content omitted from text egress"
    try:
        return data.decode("utf-8"), ""
    except UnicodeDecodeError:
        return None, "non-UTF-8 content omitted from text egress"


def assess_privacy(config: ScanConfig, inventory: InventoryResult) -> PrivacyAssessment:
    """Inspect eligible text deterministically and return metadata-only privacy results."""
    policy = RedactionPolicy(
        level=config.redaction_level,
        sensitive_path_patterns=config.sensitive_paths,
    )
    rows: list[ArtifactPrivacy] = []
    warnings: list[str] = []
    redaction_count = 0
    sensitive_path_count = 0
    files_selected = 0
    bytes_selected = 0
    omitted = 0

    for artifact in inventory.artifacts:
        sensitive = path_is_sensitive(artifact.locator, policy.sensitive_path_patterns)
        locator = safe_locator(artifact.id) if sensitive else artifact.locator
        if sensitive:
            sensitive_path_count += 1

        if artifact.path_kind != "file" or artifact.excluded:
            state = "path_redacted" if sensitive else "none"
            rows.append(ArtifactPrivacy(
                artifact_id=artifact.id,
                locator=artifact.locator,
                safe_locator=locator,
                redaction_state=state,
                sensitive_path=sensitive,
                omission_reason="sensitive path omitted" if sensitive else "not an egress text file",
            ))
            continue

        if sensitive:
            rows.append(ArtifactPrivacy(
                artifact_id=artifact.id,
                locator=artifact.locator,
                safe_locator=locator,
                redaction_state="fully_omitted",
                sensitive_path=True,
                omission_reason="sensitive path omitted by policy",
            ))
            omitted += 1
            continue

        if not artifact.content_identity.startswith("sha256:"):
            rows.append(ArtifactPrivacy(
                artifact_id=artifact.id,
                locator=artifact.locator,
                safe_locator=artifact.locator,
                redaction_state="metadata_only",
                omission_reason="content was not identity-complete within scan resource limits",
            ))
            omitted += 1
            continue

        path = inventory.root / Path(*artifact.locator.split("/"))
        text, reason = _read_text_bounded(path, min(config.max_file_bytes, config.max_total_bytes))
        if text is None:
            rows.append(ArtifactPrivacy(
                artifact_id=artifact.id,
                locator=artifact.locator,
                safe_locator=artifact.locator,
                redaction_state="metadata_only",
                omission_reason=reason,
            ))
            omitted += 1
            if reason.startswith("unreadable:"):
                warnings.append(f"Privacy read failed for {artifact.locator}: {reason}")
            continue

        result = redact_value(text, policy)
        redaction_count += result.count
        files_selected += 1
        bytes_selected += len(result.value.encode("utf-8"))
        rows.append(ArtifactPrivacy(
            artifact_id=artifact.id,
            locator=artifact.locator,
            safe_locator=artifact.locator,
            redaction_state="content_redacted" if result.changed else "none",
            redaction_count=result.count,
            categories=result.categories,
            sensitive_path=False,
            egress_eligible=True,
            egress_bytes=len(result.value.encode("utf-8")),
        ))

    return PrivacyAssessment(
        artifacts=tuple(rows),
        redaction_count=redaction_count,
        sensitive_path_count=sensitive_path_count,
        files_selected=files_selected,
        bytes_selected=bytes_selected,
        files_omitted_by_policy=omitted,
        sensitive_paths_omitted=sensitive_path_count,
        warnings=tuple(warnings),
    )


def build_egress_preview(
    source: Mapping[str, Any] | ScanConfig,
    inventory: InventoryResult | None = None,
) -> EgressPreview:
    """Return deterministic egress metadata without transmitting data.

    The public v0.2 API accepts canonical Scan state. Internal callers may also pass
    ``(ScanConfig, InventoryResult)`` while constructing that state or serving the
    CLI preview command.
    """
    if isinstance(source, ScanConfig):
        if inventory is None:
            raise TypeError("InventoryResult is required when build_egress_preview receives ScanConfig")
        assessment = assess_privacy(source, inventory)
        return EgressPreview(
            files_selected=assessment.files_selected,
            bytes_selected=assessment.bytes_selected,
            files_omitted_by_policy=assessment.files_omitted_by_policy,
            redaction_count=assessment.redaction_count,
            sensitive_paths_omitted=assessment.sensitive_paths_omitted,
            privacy_mode=source.privacy_mode,
            network_action="none",
        )

    privacy = source.get("privacy")
    extensions = source.get("extensions")
    if not isinstance(privacy, Mapping) or not isinstance(extensions, Mapping):
        raise ValueError("Canonical Scan state must contain privacy and extensions objects")
    preview = extensions.get("privacy_egress_preview")
    if not isinstance(preview, Mapping):
        raise ValueError("Canonical Scan state is missing extensions.privacy_egress_preview")
    required = ("files_selected", "bytes_selected", "files_omitted_by_policy", "sensitive_paths_omitted")
    for key in required:
        if type(preview.get(key)) is not int or preview[key] < 0:
            raise ValueError(f"privacy_egress_preview.{key} must be a non-negative integer")
    redaction_count = privacy.get("redaction_count")
    mode = privacy.get("mode")
    if type(redaction_count) is not int or redaction_count < 0:
        raise ValueError("privacy.redaction_count must be a non-negative integer")
    if not isinstance(mode, str) or not mode:
        raise ValueError("privacy.mode must be a nonempty string")
    if preview.get("network_action") != "none":
        raise ValueError("v0.2 egress preview network_action must be none")
    return EgressPreview(
        files_selected=preview["files_selected"],
        bytes_selected=preview["bytes_selected"],
        files_omitted_by_policy=preview["files_omitted_by_policy"],
        redaction_count=redaction_count,
        sensitive_paths_omitted=preview["sensitive_paths_omitted"],
        privacy_mode=mode,
        network_action="none",
    )


def prepare_text_for_egress(path: Path, policy: RedactionPolicy, *, max_bytes: int) -> RedactionResult:
    """Return redacted text for a future bounded provider adapter; never transmits it."""
    text, reason = _read_text_bounded(Path(path), max_bytes)
    if text is None:
        raise ValueError(reason)
    return redact_value(text, policy)
