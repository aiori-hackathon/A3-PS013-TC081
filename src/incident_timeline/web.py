"""Local web dashboard for searching and tracing normalized incident events."""

from __future__ import annotations

import json
import tempfile
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from typing import Any

from .evidence import Case, EvidenceError, check_source, verify, verify_chain
from .exports import export_json, export_pdf, filter_event_dicts, load_case_export, safe_case_filename
from .models import load_events


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


class TracefuseHandler(BaseHTTPRequestHandler):
    """Request handler is bound to a single case by ``serve_case``."""

    case_root: Path

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep server logs compact and avoid printing query strings/raw event content.
        sys.stderr.write(f"TRACEFUSE {self.address_string()} - {fmt % args}\n")

    @property
    def case(self) -> Case:
        return Case(self.case_root)

    def _send(self, status: int, body: bytes, content_type: str = "application/json; charset=utf-8",
              filename: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        if filename:
            safe = filename.replace('"', "")
            self.send_header("Content-Disposition", f'attachment; filename="{safe}"')
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, status: int, message: str) -> None:
        self._send(status, _json_bytes({"error": message}))

    @staticmethod
    def _filters(params: dict[str, list[str]]) -> dict[str, str | None]:
        return {key: (params.get(key, [""])[0] or None) for key in ("q", "source", "action", "outcome", "start", "end")}

    def _events(self) -> list[dict[str, Any]]:
        event_path = self.case.output_dir / "events.jsonl"
        if not event_path.is_file():
            raise EvidenceError(f"normalized timeline not found at {event_path}; run `incident-timeline parse {self.case.root}` first")
        return [event.to_dict() for event in load_events(event_path)]

    def _summary(self) -> dict[str, Any]:
        case = self.case
        metadata = case.load_meta()
        events = self._events()
        summary_path = case.output_dir / "summary.json"
        parsed = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}
        verification = verify(case, record=False)
        source_list = []
        for s in case.sources():
            source_list.append({
                "source_id": s.get("source_id"), "source_type": s.get("source_type"),
                "original_name": s.get("original_name"), "sha256": s.get("sha256"),
                "host": s.get("host"), "tz": s.get("tz"),
                "skew_offset_s": s.get("skew_offset_s") or 0.0,
            })
        return {
            "case_id": metadata.get("case_id", case.root.name),
            "events": len(events), "source_count": len(source_list),
            "gaps": parsed.get("gaps", 0),
            "first_ts_utc": parsed.get("first_ts_utc") or (events[0].get("ts_utc") if events else None),
            "last_ts_utc": parsed.get("last_ts_utc") or (events[-1].get("ts_utc") if events else None),
            "actions": sorted({e.get("action") for e in events if e.get("action")}),
            "sources": source_list,
            "integrity_ok": verification.ok,
            "integrity_issues": verification.files_bad + verification.chain_errors,
        }

    def _evidence_line(self, params: dict[str, list[str]]) -> dict[str, Any]:
        sid = (params.get("source_id") or [""])[0]
        line_text = (params.get("line_no") or [""])[0]
        if not sid or not line_text:
            raise ValueError("source_id and line_no are required")
        try:
            line_no = int(line_text)
        except ValueError as exc:
            raise ValueError("line_no must be an integer") from exc
        if line_no < 1:
            raise ValueError("line_no must be a positive integer")
        source = self.case.source(sid)
        chain_errors = verify_chain(self.case)
        if chain_errors:
            raise EvidenceError("Custody chain integrity check failed: " + "; ".join(chain_errors[:3]))
        problem = check_source(self.case, sid)
        if problem:
            raise EvidenceError(f"Evidence integrity check failed: {problem}")
        collect_record = next((r for r in self.case.read_custody()
                               if r.get("action") == "collect" and r.get("source_id") == sid), None)
        if not collect_record:
            raise EvidenceError(f"No collection custody record found for {sid}")
        evidence_path = (self.case.root / collect_record["evidence_path"]).resolve()
        try:
            evidence_path.relative_to(self.case.root.resolve())
        except ValueError as exc:
            raise EvidenceError("Evidence path escaped the case directory; refusing to read it") from exc
        with evidence_path.open("r", encoding="utf-8", errors="replace") as fh:
            for current, line in enumerate(fh, start=1):
                if current == line_no:
                    return {
                        "source_id": sid, "source_file": source.get("original_name"),
                        "line_no": line_no, "raw_line": line.rstrip("\r\n"),
                        "file_sha256": collect_record.get("sha256"),
                        "integrity_verified": True,
                    }
        raise ValueError(f"line {line_no} does not exist in evidence source {sid}")

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        url = urlsplit(self.path)
        params = parse_qs(url.query, keep_blank_values=True)
        try:
            if url.path in ("/", "/index.html"):
                html_path = Path(__file__).with_name("dashboard.html")
                self._send(200, html_path.read_bytes(), "text/html; charset=utf-8")
                return
            if url.path == "/api/summary":
                self._send(200, _json_bytes(self._summary()))
                return
            if url.path == "/api/events":
                all_events = filter_event_dicts(self._events(), self._filters(params))
                try:
                    limit = min(max(int((params.get("limit") or ["50"])[0]), 1), 500)
                    offset = max(int((params.get("offset") or ["0"])[0]), 0)
                except ValueError as exc:
                    raise ValueError("limit and offset must be integers") from exc
                self._send(200, _json_bytes({"events": all_events[offset:offset + limit], "total": len(all_events), "offset": offset, "limit": limit}))
                return
            if url.path == "/api/evidence":
                self._send(200, _json_bytes(self._evidence_line(params)))
                return
            if url.path == "/export/events.json":
                report = load_case_export(self.case.root, self._filters(params))
                filename = f"tracefuse-{safe_case_filename(str(report['case_id']))}-timeline.json"
                self._send(200, _json_bytes(report), "application/json; charset=utf-8", filename)
                return
            if url.path == "/export/report.pdf":
                filename = f"tracefuse-{safe_case_filename(self.case.load_meta().get('case_id', self.case.root.name))}-report.pdf"
                with tempfile.TemporaryDirectory(prefix="tracefuse-export-") as tmp_dir:
                    path = Path(tmp_dir) / filename
                    export_pdf(self.case.root, path, self._filters(params))
                    self._send(200, path.read_bytes(), "application/pdf", filename)
                return
            self._fail(404, "Not found")
        except ValueError as exc:
            self._fail(400, str(exc))
        except EvidenceError as exc:
            self._fail(409, str(exc))
        except FileNotFoundError as exc:
            self._fail(404, str(exc))
        except RuntimeError as exc:
            self._fail(501, str(exc))
        except Exception as exc:  # prevent tracebacks from being rendered to remote clients
            print(f"TRACEFUSE request error on {url.path}: {type(exc).__name__}: {exc}", file=sys.stderr)
            self._fail(500, "Internal server error; see the local terminal for details")


def serve_case(case_path: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    """Serve the read-only dashboard for one already-parsed case."""
    case = Case.open(case_path)
    if not (case.output_dir / "events.jsonl").is_file():
        raise EvidenceError(f"normalized timeline missing; run `incident-timeline parse {case.root}` first")
    if not (Path(__file__).with_name("dashboard.html")).is_file():
        raise FileNotFoundError("dashboard.html is missing from the incident_timeline package")
    handler_class = type("BoundTracefuseHandler", (TracefuseHandler,), {"case_root": case.root.resolve()})
    server = ThreadingHTTPServer((host, port), handler_class)
    actual_host, actual_port = server.server_address[:2]
    print(f"TRACEFUSE dashboard for case {case.load_meta().get('case_id', case.root.name)}")
    print(f"Open http://{actual_host if actual_host not in ('0.0.0.0', '::') else '127.0.0.1'}:{actual_port} in your browser")
    print("Local dashboard is read-only. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping TRACEFUSE dashboard…")
    finally:
        server.server_close()
