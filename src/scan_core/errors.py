"""Stable Scan error types and CLI exit codes."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    COMMAND_ERROR = 2
    SOURCE_ERROR = 3
    COVERAGE_THRESHOLD = 4
    VALIDATION_FAILED = 5
    PRIVACY_BLOCKED = 6
    RESOURCE_LIMIT = 7
    INTERNAL_ERROR = 10


class ScanError(Exception):
    """Base class for expected Scan failures."""


class CommandError(ScanError):
    """Invalid or unavailable command/configuration."""


class SourceError(ScanError):
    """Target/source path could not be read safely."""


class CoverageThresholdError(ScanError):
    """Scan completed but the requested coverage threshold was not met."""


class PrivacyBlockedError(ScanError):
    """Privacy/redaction policy blocked the requested operation."""


class ResourceLimitError(ScanError):
    """A configured resource or safety limit was reached."""


class ValidationError(ScanError, ValueError):
    """Scan state or report failed structural validation."""


class UnsupportedSchemaError(ValidationError):
    """The requested Scan state version is not implemented."""


class UnsafeReportError(ValidationError):
    """HTML violates the static, self-contained report safety contract."""
