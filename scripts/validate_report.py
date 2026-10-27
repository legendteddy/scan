#!/usr/bin/env python3
"""Compatibility wrapper for the packaged Scan validator."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scan_core.validate import (  # noqa: E402
    CHECK_CATEGORIES,
    CHECK_STATUSES,
    COLLECTIONS,
    FIELDS,
    ORIGINS,
    STATE_ID,
    STATUSES,
    VERIFICATION,
    load_report_state,
    require,
    validate,
    validate_json,
    validate_path,
    validate_report,
    validate_state,
)


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 2, "Usage: validate_report.py REPORT.html")
        validate_report(sys.argv[1])
    except (KeyError, ValueError, OSError, TypeError) as error:
        print("FAIL:", error, file=sys.stderr)
        raise SystemExit(1)
