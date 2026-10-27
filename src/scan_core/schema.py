"""Access to bundled Scan structural JSON Schemas."""

from __future__ import annotations

from importlib.resources import files
import json
from typing import Any

from .errors import CommandError


SUPPORTED_SCHEMA_FILES = {
    "1.2": "scan-state-1.2.schema.json",
    "1.3": "scan-state-1.3.schema.json",
    "1.4": "scan-state-1.4.schema.json",
}


def schema_text(version: str = "1.4") -> str:
    try:
        filename = SUPPORTED_SCHEMA_FILES[version]
    except KeyError as error:
        raise CommandError(f"Unsupported schema version: {version}") from error
    return files("scan_core.schemas").joinpath(filename).read_text(encoding="utf-8")


def schema_object(version: str = "1.4") -> dict[str, Any]:
    value = json.loads(schema_text(version))
    if not isinstance(value, dict):
        raise CommandError(f"Bundled schema {version} is not a JSON object")
    return value
