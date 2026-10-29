"""Read-only local HTTP history viewer for validated Scan state receipts."""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

from .compare import compare_states
from .render import render_html
from .state import canonical_state_json, state_digest
from .validate import validate_state

MAX_RECEIPT_BYTES = 32 * 1024 * 1024
MAX_RECEIPTS = 256
_ID_RE = re.compile(r"^[0-9a-f]{20}$")


@dataclass(frozen=True)
class ReceiptEntry:
    id: str
    path: Path
    state: dict[str, Any]
    digest: str
    completed_at: str
    project_name: str
    finding_count: int
    unknown_count: int
    analysis_complete: bool

    @property
    def lineage(self) -> tuple[str, tuple[str, ...]]:
        project = self.state["project"]
        return str(project["name"]), tuple(str(value) for value in project.get("source_locators", []))


@dataclass(frozen=True)
class HistoryCatalog:
    source: Path
    entries: tuple[ReceiptEntry, ...]
    skipped_count: int

    def by_id(self, ident: str) -> ReceiptEntry | None:
        return next((entry for entry in self.entries if entry.id == ident), None)


def _h(value: object) -> str:
    return escape(str(value), quote=True)


def _entry(state: Mapping[str, Any], path: Path) -> ReceiptEntry:
    validated = validate_state(dict(state))
    if validated.get("schema_version") not in {"1.3", "1.4"}:
        raise ValueError("local viewer requires Scan state schema 1.3 or 1.4")
    digest = state_digest(validated)
    ident = digest.removeprefix("sha256:")[:20]
    return ReceiptEntry(
        id=ident,
        path=path,
        state=validated,
        digest=digest,
        completed_at=str(validated["run"]["completed_at"]),
        project_name=str(validated["project"]["name"]),
        finding_count=len(validated["findings"]),
        unknown_count=len(validated["unknowns"]),
        analysis_complete=bool(validated["coverage"]["analysis_complete"]),
    )


def _load_receipt(path: Path) -> ReceiptEntry:
    size = path.stat().st_size
    if size > MAX_RECEIPT_BYTES:
        raise ValueError(f"state receipt exceeds local viewer limit ({MAX_RECEIPT_BYTES} bytes)")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON state receipt: {path}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"Scan state receipt must be a JSON object: {path}")
    return _entry(payload, path)


def discover_receipts(source: Path | str) -> HistoryCatalog:
    """Discover bounded validated state receipts without serving arbitrary files."""
    root = Path(source)
    if not root.exists():
        raise ValueError(f"history source does not exist: {root}")
    if root.is_symlink():
        raise ValueError(f"history source symlinks are not allowed: {root}")
    if root.is_file():
        candidates = [root]
    elif root.is_dir():
        candidates = sorted(root.glob("*.json"))
        if len(candidates) > MAX_RECEIPTS:
            raise ValueError(f"history source exceeds local viewer receipt limit ({MAX_RECEIPTS})")
    else:
        raise ValueError(f"history source must be a file or directory: {root}")

    entries: list[ReceiptEntry] = []
    skipped = 0
    seen: set[str] = set()
    for path in candidates:
        if path.is_symlink() or not path.is_file():
            skipped += 1
            continue
        try:
            entry = _load_receipt(path)
        except (OSError, ValueError, KeyError, TypeError):
            skipped += 1
            continue
        if entry.digest in seen:
            skipped += 1
            continue
        seen.add(entry.digest)
        entries.append(entry)
    if not entries:
        raise ValueError("no valid Scan state receipts found")
    entries.sort(key=lambda entry: (entry.completed_at, entry.id), reverse=True)
    return HistoryCatalog(source=root, entries=tuple(entries), skipped_count=skipped)


def _style() -> str:
    return """
    :root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:#171717;background:#f5f5f3}
    body{max-width:1080px;margin:0 auto;padding:32px 20px 64px}a{color:#1d4ed8}code{font-family:ui-monospace,monospace}
    h1{font-size:2rem;margin-bottom:.35rem}p{line-height:1.55}.muted{color:#666}.card{background:#fff;border:1px solid #ddd;border-radius:14px;padding:18px;margin:14px 0}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}.metric{background:#fafafa;border:1px solid #e5e5e5;border-radius:10px;padding:12px}
    .metric b{display:block;font-size:1.35rem}.links{display:flex;gap:14px;flex-wrap:wrap}.ok{color:#166534}.warn{color:#92400e}
    table{width:100%;border-collapse:collapse;background:#fff}th,td{text-align:left;padding:10px;border-bottom:1px solid #e5e5e5;vertical-align:top}
    @media(max-width:640px){body{padding:20px 12px}th:nth-child(3),td:nth-child(3){display:none}}
    """


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{_h(title)}</title><style>{_style()}</style></head><body>{body}</body></html>"
    )


def build_index_html(catalog: HistoryCatalog) -> str:
    rows: list[str] = []
    for index, entry in enumerate(catalog.entries):
        previous = next((older for older in catalog.entries[index + 1:] if older.lineage == entry.lineage), None)
        compare = (
            f"<a href='/compare/{previous.id}/{entry.id}'>Compare with prior receipt</a>"
            if previous is not None else "No prior same-project receipt in this source"
        )
        status = "complete" if entry.analysis_complete else "incomplete"
        rows.append(
            "<tr>"
            f"<td><strong>{_h(entry.project_name)}</strong><br><code>{_h(entry.id)}</code></td>"
            f"<td>{_h(entry.completed_at)}</td><td>{_h(status)}</td>"
            f"<td>{entry.finding_count} findings · {entry.unknown_count} unknowns</td>"
            f"<td><a href='/report/{entry.id}'>Report</a> · <a href='/state/{entry.id}.json'>State</a><br>{compare}</td>"
            "</tr>"
        )
    skipped = (
        f"<p class='muted'>{catalog.skipped_count} invalid or duplicate JSON receipt(s) were ignored.</p>"
        if catalog.skipped_count else ""
    )
    body = (
        "<p class='muted'>Scan local viewer · read-only · only validated state receipts are exposed.</p>"
        "<h1>Scan report history</h1>"
        f"<p>{len(catalog.entries)} validated receipt(s) from <code>{_h(catalog.source)}</code>.</p>{skipped}"
        "<div class='card'><p><strong>Boundary:</strong> this server does not expose the project tree, execute target code, or fetch remote data.</p></div>"
        "<table><thead><tr><th>Project</th><th>Completed</th><th>Analysis</th><th>Receipts</th><th>Open</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
    )
    return _page("Scan report history", body)


def _same_lineage(old: ReceiptEntry, new: ReceiptEntry) -> bool:
    return old.lineage == new.lineage


def build_compare_html(old: ReceiptEntry, new: ReceiptEntry) -> str:
    if not _same_lineage(old, new):
        raise ValueError("comparison requires receipts from the same project lineage")
    comparison = compare_states(old.state, new.state).as_dict()
    artifacts = comparison["artifacts"]
    findings = comparison["findings"]
    unknowns = comparison["unknowns"]
    metrics = (
        ("Artifacts added", len(artifacts["added"])), ("Artifacts changed", len(artifacts["changed"])),
        ("Artifacts removed", len(artifacts["removed"])), ("New findings", len(findings["new"])),
        ("Resolved findings", len(findings["resolved"])), ("New unknowns", len(unknowns["new"])),
        ("Resolved unknowns", len(unknowns["resolved"])),
    )
    cards = "".join(f"<div class='metric'><b>{value}</b>{_h(label)}</div>" for label, value in metrics)
    body = (
        "<p><a href='/'>← History</a></p>"
        f"<h1>{_h(new.project_name)} comparison</h1>"
        f"<p class='muted'><code>{_h(old.id)}</code> → <code>{_h(new.id)}</code></p>"
        f"<div class='grid'>{cards}</div>"
        "<div class='card'><p><strong>Interpretation:</strong> resolved means absent from the newer canonical state. It is not proof that an issue was fixed.</p>"
        f"<p>Snapshot relation: <strong>{_h(comparison['snapshot_relation'])}</strong>.</p></div>"
        f"<p class='links'><a href='/report/{old.id}'>Older report</a><a href='/report/{new.id}'>Newer report</a>"
        f"<a href='/compare-json/{old.id}/{new.id}'>Comparison JSON</a></p>"
    )
    return _page(f"{new.project_name} comparison", body)


class HistoryApp:
    def __init__(self, catalog: HistoryCatalog):
        self.catalog = catalog

    def _entry(self, ident: str) -> ReceiptEntry | None:
        if not _ID_RE.fullmatch(ident):
            return None
        return self.catalog.by_id(ident)

    def route(self, raw_path: str) -> tuple[int, str, bytes, str | None]:
        path = urlsplit(raw_path).path
        if path == "/":
            return 200, "text/html; charset=utf-8", build_index_html(self.catalog).encode("utf-8"), "index"
        if path == "/healthz":
            return 200, "text/plain; charset=utf-8", b"ok\n", None
        match = re.fullmatch(r"/report/([0-9a-f]{20})", path)
        if match:
            entry = self._entry(match.group(1))
            if entry is not None:
                return 200, "text/html; charset=utf-8", render_html(entry.state).encode("utf-8"), "report"
        match = re.fullmatch(r"/state/([0-9a-f]{20})\.json", path)
        if match:
            entry = self._entry(match.group(1))
            if entry is not None:
                return 200, "application/json; charset=utf-8", (canonical_state_json(entry.state) + "\n").encode("utf-8"), None
        match = re.fullmatch(r"/compare/([0-9a-f]{20})/([0-9a-f]{20})", path)
        if match:
            old, new = self._entry(match.group(1)), self._entry(match.group(2))
            if old is not None and new is not None:
                try:
                    body = build_compare_html(old, new).encode("utf-8")
                except ValueError as error:
                    return 409, "text/plain; charset=utf-8", (str(error) + "\n").encode("utf-8"), None
                return 200, "text/html; charset=utf-8", body, "index"
        match = re.fullmatch(r"/compare-json/([0-9a-f]{20})/([0-9a-f]{20})", path)
        if match:
            old, new = self._entry(match.group(1)), self._entry(match.group(2))
            if old is not None and new is not None:
                if not _same_lineage(old, new):
                    return 409, "text/plain; charset=utf-8", b"comparison requires receipts from the same project lineage\n", None
                payload = compare_states(old.state, new.state).as_dict()
                body = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
                return 200, "application/json; charset=utf-8", body, None
        return 404, "text/plain; charset=utf-8", b"not found\n", None


def _handler(app: HistoryApp, *, quiet: bool):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ScanLocalViewer/1"
        protocol_version = "HTTP/1.1"

        def _respond(self, *, head_only: bool = False) -> None:
            status, content_type, body, page_kind = app.route(self.path)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            if page_kind == "index":
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            elif page_kind == "report":
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.end_headers()
            if not head_only:
                self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            self._respond()

        def do_HEAD(self) -> None:  # noqa: N802
            self._respond(head_only=True)

        def log_message(self, format: str, *args: object) -> None:
            if not quiet:
                super().log_message(format, *args)

    return Handler


def _loopback_host(host: str) -> bool:
    return host.strip().lower() in {"127.0.0.1", "localhost"}


def create_server(
    source: Path | str,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    allow_network: bool = False,
    quiet: bool = False,
) -> tuple[ThreadingHTTPServer, HistoryCatalog]:
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    if not _loopback_host(host) and not allow_network:
        raise ValueError("non-loopback bind requires --allow-network")
    catalog = discover_receipts(source)
    app = HistoryApp(catalog)
    server = ThreadingHTTPServer((host, port), _handler(app, quiet=quiet))
    server.daemon_threads = True
    return server, catalog
