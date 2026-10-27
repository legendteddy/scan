"""Local-only baseline resolution for repeated Scan runs."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from .errors import ResourceLimitError, SourceError, ValidationError
from .validate import reject_constant, unique_keys, validate_state

DEFAULT_MAX_STATE_BYTES = 64_000_000


@dataclass(frozen=True)
class BaselineResolution:
    mode: str
    status: str
    state: Mapping[str, Any] | None = None
    warning: str | None = None


def load_state_file(path: Path, *, max_state_bytes: int = DEFAULT_MAX_STATE_BYTES, explicit: bool = True) -> dict[str, Any]:
    try:
        stat = path.stat()
    except OSError as error:
        raise SourceError(f"Cannot access baseline state: {path}") from error
    if not path.is_file():
        raise SourceError(f"Baseline state is not a regular file: {path}")
    if stat.st_size > max_state_bytes:
        message = f"Baseline state exceeds configured ceiling ({stat.st_size} > {max_state_bytes} bytes)"
        if explicit:
            raise ResourceLimitError(message)
        raise ValidationError(message)
    try:
        with path.open(encoding="utf-8") as stream:
            state = json.load(stream, object_pairs_hook=unique_keys, parse_constant=reject_constant)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"Cannot parse baseline state: {error}") from error
    if not isinstance(state, dict):
        raise ValidationError("Baseline state must be a JSON object")
    if state.get("schema_version") not in {"1.3", "1.4"}:
        raise ValidationError("Baseline state must use schema_version 1.3 or 1.4")
    validate_state(state)
    return state


def resolve_baseline(
    *,
    mode: str,
    output_state: Path | None,
    explicit_path: Path | None = None,
    max_state_bytes: int = DEFAULT_MAX_STATE_BYTES,
) -> BaselineResolution:
    """Resolve a local baseline without network access or filesystem searching."""
    if mode == "none":
        return BaselineResolution(mode="none", status="disabled")
    if mode == "explicit":
        if explicit_path is None:
            raise SourceError("Explicit baseline path was not supplied")
        path = Path(explicit_path)
        if not path.exists():
            raise SourceError(f"Baseline state does not exist: {path}")
        state = load_state_file(path, max_state_bytes=max_state_bytes, explicit=True)
        return BaselineResolution(mode="explicit", status="used", state=state)
    if mode != "auto":
        raise ValueError(f"Unsupported baseline mode: {mode}")
    if output_state is None:
        return BaselineResolution(mode="auto", status="not_found")
    path = Path(output_state)
    if not path.exists():
        return BaselineResolution(mode="auto", status="not_found")
    try:
        state = load_state_file(path, max_state_bytes=max_state_bytes, explicit=False)
    except ValidationError as error:
        return BaselineResolution(
            mode="auto",
            status="invalid",
            warning=f"Automatic baseline ignored: {error}",
        )
    except SourceError as error:
        return BaselineResolution(
            mode="auto",
            status="invalid",
            warning=f"Automatic baseline ignored: {error}",
        )
    return BaselineResolution(mode="auto", status="used", state=state)
