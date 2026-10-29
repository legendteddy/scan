"""Privacy-safe post-run contribution receipts for AI agents using Scan.

Every invocation writes a bounded machine-readable receipt. External GitHub
submission happens only when explicitly enabled by caller/host policy. Target-
controlled project configuration is never consulted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib import error, parse, request

from .version import __version__

PROTOCOL_VERSION = "1"
DEFAULT_REPOSITORY = "legendteddy/scan"
MAX_TEXT = 800
MAX_ITEMS = 20
MAX_STATE_BYTES = 64_000_000
MAX_RECEIPT_BYTES = 128_000
MAX_FLUSH_ITEMS = 20
VALID_TEST_RESULTS = {"pass", "fail", "partial", "skipped", "unknown"}
_TRUE_VALUES = {"1", "true", "yes", "on"}
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b"),
    re.compile(r"(?i)\b(token|secret|password|api[_-]?key)\s*[:=]\s*[^\s,;]+"),
)
_WINDOWS_PATH = re.compile(r"(?i)(?:[A-Z]:\\+(?:[^\s\\/:*?\"<>|]+\\+)+[^\s\\/:*?\"<>|]*)")
_POSIX_PATH = re.compile(r"(?<![A-Za-z0-9._-])/(?:[^\s/]+/)+[^\s/]+")


def _sanitize_text(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    text = " ".join(value.replace("\x00", " ").split())
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = _WINDOWS_PATH.sub("[PATH]", text)
    text = _POSIX_PATH.sub("[PATH]", text)
    if len(text) > MAX_TEXT:
        text = text[: MAX_TEXT - 1] + "…"
    return text


def _bounded_items(values: Iterable[str], *, label: str) -> list[str]:
    items = [_sanitize_text(value, label=label) for value in values]
    items = [item for item in items if item]
    if len(items) > MAX_ITEMS:
        raise ValueError(f"{label} accepts at most {MAX_ITEMS} entries")
    return items


def _parse_tests(values: Iterable[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw in values:
        if "=" not in raw:
            raise ValueError("--test must use NAME=RESULT")
        name, result = raw.rsplit("=", 1)
        result = result.strip().lower()
        if result not in VALID_TEST_RESULTS:
            allowed = ", ".join(sorted(VALID_TEST_RESULTS))
            raise ValueError(f"test result must be one of: {allowed}")
        clean_name = _sanitize_text(name, label="test name")
        if not clean_name:
            raise ValueError("test name must not be empty")
        rows.append({"name": clean_name, "result": result})
    if len(rows) > MAX_ITEMS:
        raise ValueError(f"--test accepts at most {MAX_ITEMS} entries")
    return rows


def _state_binding(path: Path | None) -> dict[str, str] | None:
    if path is None:
        return None
    raw = path.read_bytes()
    if len(raw) > MAX_STATE_BYTES:
        raise ValueError(f"state file exceeds {MAX_STATE_BYTES} bytes")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    schema_version = "unknown"
    try:
        value = json.loads(raw.decode("utf-8-sig"))
        if isinstance(value, dict) and isinstance(value.get("schema_version"), str):
            schema_version = value["schema_version"]
    except (UnicodeError, json.JSONDecodeError):
        pass
    return {"digest": digest, "schema_version": schema_version}


def _fingerprint_payload(receipt: Mapping[str, Any]) -> str:
    stable = {
        "protocol_version": receipt["protocol_version"],
        "scan_version": receipt["scan_version"],
        "state": receipt.get("state"),
        "tests": receipt["tests"],
        "feedback": receipt["feedback"],
        "issues": receipt["issues"],
    }
    encoded = json.dumps(stable, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_receipt(
    *,
    state_path: Path | None = None,
    agent: str = "",
    host: str = "",
    tests: Iterable[str] = (),
    feedback: Iterable[str] = (),
    issues: Iterable[str] = (),
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build a bounded receipt containing product observations, never target bytes."""
    receipt: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "scan_version": __version__,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "agent": _sanitize_text(agent, label="agent"),
        "host": _sanitize_text(host, label="host"),
        "state": _state_binding(state_path),
        "tests": _parse_tests(tests),
        "feedback": _bounded_items(feedback, label="feedback"),
        "issues": _bounded_items(issues, label="issue"),
        "privacy": {
            "target_content_included": False,
            "raw_logs_included": False,
            "absolute_target_paths_included": False,
        },
    }
    receipt["fingerprint"] = _fingerprint_payload(receipt)
    receipt["receipt_id"] = "scan-feedback-" + receipt["fingerprint"][:16]
    return receipt


def validate_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an existing receipt before retrying any external submission."""
    if value.get("protocol_version") != PROTOCOL_VERSION:
        raise ValueError(f"feedback receipt protocol_version must be {PROTOCOL_VERSION}")
    scan_version = value.get("scan_version")
    created_at = value.get("created_at")
    if not isinstance(scan_version, str) or not scan_version:
        raise ValueError("feedback receipt scan_version must be nonempty text")
    if not isinstance(created_at, str) or not created_at:
        raise ValueError("feedback receipt created_at must be nonempty text")

    agent = value.get("agent", "")
    host = value.get("host", "")
    if _sanitize_text(agent, label="agent") != agent or _sanitize_text(host, label="host") != host:
        raise ValueError("feedback receipt agent/host fields are not privacy-sanitized")

    tests = value.get("tests")
    if not isinstance(tests, list) or len(tests) > MAX_ITEMS:
        raise ValueError("feedback receipt tests must be a bounded array")
    normalized_tests: list[dict[str, str]] = []
    for index, row in enumerate(tests):
        if not isinstance(row, Mapping):
            raise ValueError(f"feedback receipt tests[{index}] must be an object")
        name = row.get("name")
        result = row.get("result")
        if not isinstance(name, str) or not name or _sanitize_text(name, label="test name") != name:
            raise ValueError(f"feedback receipt tests[{index}].name is invalid")
        if result not in VALID_TEST_RESULTS:
            raise ValueError(f"feedback receipt tests[{index}].result is invalid")
        normalized_tests.append({"name": name, "result": result})

    def checked_text_list(field: str) -> list[str]:
        rows = value.get(field)
        if not isinstance(rows, list) or len(rows) > MAX_ITEMS:
            raise ValueError(f"feedback receipt {field} must be a bounded array")
        normalized: list[str] = []
        for index, item in enumerate(rows):
            if not isinstance(item, str) or not item:
                raise ValueError(f"feedback receipt {field}[{index}] must be nonempty text")
            if _sanitize_text(item, label=field) != item:
                raise ValueError(f"feedback receipt {field}[{index}] is not privacy-sanitized")
            normalized.append(item)
        return normalized

    feedback = checked_text_list("feedback")
    issues = checked_text_list("issues")

    state = value.get("state")
    normalized_state: dict[str, str] | None = None
    if state is not None:
        if not isinstance(state, Mapping):
            raise ValueError("feedback receipt state must be an object or null")
        digest = state.get("digest")
        schema_version = state.get("schema_version")
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise ValueError("feedback receipt state.digest must be sha256:<64 lowercase hex>")
        if not isinstance(schema_version, str) or not schema_version:
            raise ValueError("feedback receipt state.schema_version must be nonempty text")
        normalized_state = {"digest": digest, "schema_version": schema_version}

    privacy = value.get("privacy")
    expected_privacy = {
        "target_content_included": False,
        "raw_logs_included": False,
        "absolute_target_paths_included": False,
    }
    if privacy != expected_privacy:
        raise ValueError("feedback receipt privacy boundary is invalid")

    normalized: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "scan_version": scan_version,
        "created_at": created_at,
        "agent": agent,
        "host": host,
        "state": normalized_state,
        "tests": normalized_tests,
        "feedback": feedback,
        "issues": issues,
        "privacy": expected_privacy,
    }
    fingerprint = _fingerprint_payload(normalized)
    if value.get("fingerprint") != fingerprint:
        raise ValueError("feedback receipt fingerprint does not match receipt payload")
    receipt_id = "scan-feedback-" + fingerprint[:16]
    if value.get("receipt_id") != receipt_id:
        raise ValueError("feedback receipt_id does not match fingerprint")
    normalized["fingerprint"] = fingerprint
    normalized["receipt_id"] = receipt_id
    return normalized


def _feedback_root(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit.expanduser()
    configured = os.environ.get("SCAN_FEEDBACK_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".scan" / "feedback"


def write_receipt(receipt: dict[str, Any], *, root: Path | None = None, queued: bool) -> dict[str, Path]:
    base = _feedback_root(root)
    receipts = base / "receipts"
    receipts.mkdir(parents=True, exist_ok=True)
    receipt_path = receipts / f"{receipt['receipt_id']}.json"
    encoded = json.dumps(receipt, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    receipt_path.write_text(encoded, encoding="utf-8", newline="\n")
    paths = {"receipt": receipt_path}
    if queued:
        outbox = base / "outbox"
        outbox.mkdir(parents=True, exist_ok=True)
        queued_path = outbox / receipt_path.name
        queued_path.write_text(encoded, encoding="utf-8", newline="\n")
        paths["outbox"] = queued_path
    return paths


def _submission_authorized(mode: str) -> bool:
    if mode == "github":
        return True
    if mode == "never":
        return False
    return os.environ.get("SCAN_FEEDBACK_SUBMIT", "").strip().lower() in _TRUE_VALUES


def _github_token() -> str | None:
    for name in ("SCAN_FEEDBACK_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    return None


def _repository() -> str:
    value = os.environ.get("SCAN_FEEDBACK_REPOSITORY", DEFAULT_REPOSITORY).strip()
    if not _REPOSITORY_RE.fullmatch(value):
        raise ValueError("SCAN_FEEDBACK_REPOSITORY must use owner/repo syntax")
    return value


def _github_json(url: str, *, token: str, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    body = None if payload is None else json.dumps(payload, ensure_ascii=True).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": f"scan-skill/{__version__}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _issue_body(receipt: dict[str, Any]) -> str:
    lines = [
        f"<!-- scan-feedback-fingerprint:{receipt['fingerprint']} -->",
        "## Automated Scan agent contribution",
        "",
        f"- Scan version: `{receipt['scan_version']}`",
        f"- Receipt: `{receipt['receipt_id']}`",
    ]
    if receipt.get("agent"):
        lines.append(f"- Agent: `{receipt['agent']}`")
    if receipt.get("host"):
        lines.append(f"- Host: `{receipt['host']}`")
    if receipt.get("state"):
        lines.append(f"- State digest: `{receipt['state']['digest']}`")
        lines.append(f"- State schema: `{receipt['state']['schema_version']}`")
    lines.extend(["", "### Tests"])
    if receipt["tests"]:
        lines.extend(f"- `{row['result']}` — {row['name']}" for row in receipt["tests"])
    else:
        lines.append("- No host test result supplied.")
    lines.extend(["", "### Product feedback"])
    if receipt["feedback"]:
        lines.extend(f"- {item}" for item in receipt["feedback"])
    else:
        lines.append("- None supplied.")
    lines.extend(["", "### Scan issues observed"])
    if receipt["issues"]:
        lines.extend(f"- {item}" for item in receipt["issues"])
    else:
        lines.append("- None supplied.")
    lines.extend([
        "",
        "### Privacy boundary",
        "This receipt intentionally excludes inspected project source, raw Scan state, absolute target paths, credentials, and arbitrary logs.",
    ])
    return "\n".join(lines) + "\n"


def _issue_title(receipt: dict[str, Any]) -> str:
    if receipt["issues"]:
        candidate = receipt["issues"][0]
    elif receipt["feedback"]:
        candidate = receipt["feedback"][0]
    elif any(row["result"] == "fail" for row in receipt["tests"]):
        candidate = "Scan agent test failure"
    else:
        candidate = "Scan agent usage receipt"
    return f"[agent feedback] {candidate[:100]}"


def submit_github(receipt: dict[str, Any]) -> dict[str, Any]:
    token = _github_token()
    if not token:
        raise RuntimeError("GitHub submission authorized but no GITHUB_TOKEN/GH_TOKEN credential is available")
    repository = _repository()
    query = f'repo:{repository} "scan-feedback-fingerprint:{receipt["fingerprint"]}" in:body'
    search_url = "https://api.github.com/search/issues?q=" + parse.quote(query)
    existing = _github_json(search_url, token=token)
    if isinstance(existing, dict) and existing.get("total_count", 0):
        first = (existing.get("items") or [{}])[0]
        return {"status": "duplicate", "url": first.get("html_url"), "repository": repository}
    issue = _github_json(
        f"https://api.github.com/repos/{repository}/issues",
        token=token,
        method="POST",
        payload={"title": _issue_title(receipt), "body": _issue_body(receipt)},
    )
    return {"status": "submitted", "url": issue.get("html_url"), "repository": repository}


def record_and_maybe_submit(
    receipt: dict[str, Any], *, mode: str = "auto", root: Path | None = None
) -> dict[str, Any]:
    authorized = _submission_authorized(mode)
    submission: dict[str, Any] | None = None
    submission_error: str | None = None
    if authorized:
        try:
            submission = submit_github(receipt)
        except (RuntimeError, ValueError, OSError, error.HTTPError, error.URLError, json.JSONDecodeError) as exc:
            submission_error = _sanitize_text(str(exc), label="submission error")
    queued = not authorized or submission is None
    paths = write_receipt(receipt, root=root, queued=queued)
    status = submission["status"] if submission is not None else "queued"
    return {
        "status": status,
        "receipt_id": receipt["receipt_id"],
        "fingerprint": receipt["fingerprint"],
        "receipt_path": str(paths["receipt"]),
        "outbox_path": str(paths.get("outbox")) if paths.get("outbox") else None,
        "submission": submission,
        "submission_error": submission_error,
        "submission_authorized": authorized,
    }


def _load_queued_receipt(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("queued feedback receipt must be a regular non-symlink file")
    if path.stat().st_size > MAX_RECEIPT_BYTES:
        raise ValueError(f"queued feedback receipt exceeds {MAX_RECEIPT_BYTES} bytes")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot parse queued feedback receipt: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValueError("queued feedback receipt root must be an object")
    receipt = validate_receipt(value)
    if path.name != receipt["receipt_id"] + ".json":
        raise ValueError("queued feedback filename does not match receipt_id")
    return receipt


def flush_outbox(*, mode: str = "auto", root: Path | None = None) -> dict[str, Any]:
    """Retry a bounded batch of queued receipts when submission is already authorized."""
    authorized = _submission_authorized(mode)
    base = _feedback_root(root)
    outbox = base / "outbox"
    if not authorized:
        pending = len(list(outbox.glob("*.json"))) if outbox.is_dir() else 0
        return {
            "status": "not_authorized",
            "submission_authorized": False,
            "processed": 0,
            "submitted": 0,
            "duplicate": 0,
            "failed": 0,
            "invalid": 0,
            "pending": pending,
            "results": [],
        }
    if not outbox.is_dir():
        return {
            "status": "empty",
            "submission_authorized": True,
            "processed": 0,
            "submitted": 0,
            "duplicate": 0,
            "failed": 0,
            "invalid": 0,
            "pending": 0,
            "results": [],
        }

    candidates = sorted(outbox.glob("*.json"), key=lambda path: path.name)
    batch = candidates[:MAX_FLUSH_ITEMS]
    results: list[dict[str, Any]] = []
    submitted = duplicate = failed = invalid = 0
    for path in batch:
        try:
            receipt = _load_queued_receipt(path)
        except (OSError, ValueError) as exc:
            invalid += 1
            results.append({
                "file": path.name,
                "status": "invalid",
                "error": _sanitize_text(str(exc), label="outbox validation error"),
            })
            continue
        try:
            submission = submit_github(receipt)
        except (RuntimeError, ValueError, OSError, error.HTTPError, error.URLError, json.JSONDecodeError) as exc:
            failed += 1
            results.append({
                "file": path.name,
                "receipt_id": receipt["receipt_id"],
                "status": "failed",
                "error": _sanitize_text(str(exc), label="submission error"),
            })
            continue
        status = submission.get("status")
        if status not in {"submitted", "duplicate"}:
            failed += 1
            results.append({
                "file": path.name,
                "receipt_id": receipt["receipt_id"],
                "status": "failed",
                "error": "submission returned an unsupported status",
            })
            continue
        path.unlink()
        if status == "submitted":
            submitted += 1
        else:
            duplicate += 1
        results.append({
            "file": path.name,
            "receipt_id": receipt["receipt_id"],
            "status": status,
            "url": submission.get("url"),
        })

    pending = len(list(outbox.glob("*.json")))
    return {
        "status": "complete" if pending == 0 else "partial",
        "submission_authorized": True,
        "processed": len(batch),
        "submitted": submitted,
        "duplicate": duplicate,
        "failed": failed,
        "invalid": invalid,
        "pending": pending,
        "batch_limit": MAX_FLUSH_ITEMS,
        "results": results,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scan_core.feedback",
        description="Record privacy-safe Scan agent test/feedback receipts and submit when explicitly authorized.",
    )
    parser.add_argument("--state", type=Path)
    parser.add_argument("--agent", default="")
    parser.add_argument("--host", default="")
    parser.add_argument("--test", action="append", default=[], metavar="NAME=RESULT")
    parser.add_argument("--feedback", action="append", default=[])
    parser.add_argument("--issue", action="append", default=[])
    parser.add_argument("--submit", choices=("auto", "github", "never"), default="auto")
    parser.add_argument("--feedback-home", type=Path)
    parser.add_argument("--flush", action="store_true", help="retry a bounded batch of validated queued receipts")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.flush:
            result = flush_outbox(mode=args.submit, root=args.feedback_home)
        else:
            receipt = build_receipt(
                state_path=args.state,
                agent=args.agent,
                host=args.host,
                tests=args.test,
                feedback=args.feedback,
                issues=args.issue,
            )
            result = record_and_maybe_submit(receipt, mode=args.submit, root=args.feedback_home)
    except (OSError, ValueError) as exc:
        print(f"scan feedback error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    elif args.flush:
        print(f"Scan feedback outbox: {result['status']}")
        print(
            f"Submitted: {result['submitted']}  Duplicate: {result['duplicate']}  "
            f"Failed: {result['failed']}  Invalid: {result['invalid']}  Pending: {result['pending']}"
        )
    else:
        print(f"Scan feedback: {result['status']}")
        print(f"Receipt: {result['receipt_path']}")
        if result["outbox_path"]:
            print(f"Outbox: {result['outbox_path']}")
        if result["submission"] and result["submission"].get("url"):
            print(f"GitHub: {result['submission']['url']}")
        if result["submission_error"]:
            print(f"Submission deferred: {result['submission_error']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
