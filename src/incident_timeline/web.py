"""Local web dashboard for searching and tracing normalized incident events."""

from __future__ import annotations

import json
import gzip
import tempfile
import sys
import re
import uuid
import shutil
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from typing import Any

from .evidence import Case, EvidenceError, check_source, collect, verify, verify_chain, SOURCE_TYPES
from .exports import export_json, export_pdf, filter_event_dicts, load_case_export, safe_case_filename
from .models import load_events
from .time_analysis import build_time_analysis
from .pipeline import build_timeline
from .findings import detect as detect_findings, entities as summarize_entities

def resolve_app_case(cases_root: Path, case_id: str) -> Path:
    """Resolve uploaded cases and synthetic demo cases safely."""
    if not re.fullmatch(r"CASE-[a-f0-9]{12}", case_id):
        raise FileNotFoundError("Invalid investigation ID")

    root = cases_root.resolve()

    # Normal uploaded investigation.
    direct = (root / case_id).resolve()
    if direct.parent == root and (direct / "case.json").is_file():
        return direct

    # Synthetic demonstration investigation.
    from .scenarios import SCENARIOS

    for scenario_id in SCENARIOS:
        expected_id = "CASE-" + uuid.uuid5(
            uuid.NAMESPACE_URL, scenario_id
        ).hex[:12]

        if expected_id == case_id:
            candidate = (
                root / "demo-scenarios" / scenario_id / "case"
            ).resolve()

            if (
                candidate.is_relative_to(root)
                and (candidate / "case.json").is_file()
            ):
                return candidate

    raise FileNotFoundError("Investigation not found")


def discover_cases(cases_root: Path | str) -> dict[str, Path]:
    """Return valid case directories under a root, keyed by their folder name."""
    root = Path(cases_root).expanduser().resolve()
    found: dict[str, Path] = {}
    if not root.is_dir():
        return found
    for case_file in sorted(root.glob("*/case.json")):
        candidate = case_file.parent.resolve()
        if candidate.parent == root:
            found[candidate.name] = candidate
    # Demo/test cases are stored as <root>/<scenario>/case/case.json.
    for case_file in sorted(root.glob("*/case/case.json")):
        candidate = case_file.parent.resolve()
        if candidate.is_relative_to(root):
            found[candidate.parent.name] = candidate
    return found


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


class TracefuseHandler(BaseHTTPRequestHandler):
    """Request handler is bound to a single case by ``serve_case``."""

    case_root: Path
    cases_root: Path | None = None
    case_roots: dict[str, Path] | None = None
    app_mode: bool = False

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep server logs compact and avoid printing query strings/raw event content.
        sys.stderr.write(f"TRACEFUSE {self.address_string()} - {fmt % args}\n")

    @property
    def case(self) -> Case:
        params = parse_qs(urlsplit(self.path).query)
        selected = (params.get("case") or [""])[0]
        if self.case_roots is not None and selected:
            root = self.case_roots.get(selected)
            if root is None:
                raise FileNotFoundError("Investigation not found")
            return Case.open(root)
        if self.app_mode:
            params = parse_qs(urlsplit(self.path).query)
            case_id = (params.get("case") or [""])[0]
            if not re.fullmatch(r"CASE-[a-f0-9]{12}", case_id):
                match = re.match(r"^/case/(CASE-[a-f0-9]{12})(?:/|$)", urlsplit(self.path).path)
                case_id = match.group(1) if match else ""
            if not case_id or self.cases_root is None:
                raise FileNotFoundError("Open an investigation from the TRACEFUSE home page.")
            root = resolve_app_case(self.cases_root, case_id)
            
            return Case.open(root)
        return Case(self.case_root)

    def _send(self, status: int, body: bytes, content_type: str = "application/json; charset=utf-8",
              filename: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
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
        # Verify the collected bytes above before decoding. Gzip evidence is
        # stored compressed (its hash must remain the hash of those exact bytes),
        # but the viewer must display the same logical lines the parser saw.
        try:
            if evidence_path.suffix.lower() == ".gz":
                with gzip.open(evidence_path, "rb") as fh:
                    content = fh.read()
            else:
                content = evidence_path.read_bytes()
        except (OSError, EOFError) as exc:
            raise EvidenceError(f"Could not read collected evidence for {sid}: {exc}") from exc
        lines = content.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        lines = [line[:-1] if line.endswith(b"\r") else line for line in lines]
        if line_no > len(lines):
            raise ValueError(f"line {line_no} does not exist in evidence source {sid}")
        return {
            "source_id": sid, "source_file": source.get("original_name"),
            "line_no": line_no, "raw_line": lines[line_no - 1].decode("utf-8", errors="replace"),
            "file_sha256": collect_record.get("sha256"),
            "integrity_verified": True,
        }

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        url = urlsplit(self.path)
        if url.path != "/upload" or not self.app_mode or self.cases_root is None:
            self._fail(404, "Not found")
            return
        try:
            content_type = self.headers.get("Content-Type", "")
            if not content_type.lower().startswith("multipart/form-data"):
                raise ValueError("Choose one or more log files to upload.")
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 25 * 1024 * 1024:
                raise ValueError("Uploads must be between 1 byte and 25 MB total for this demo.")
            body = self.rfile.read(length)
            message = BytesParser(policy=policy.default).parsebytes(b"Content-Type: " + content_type.encode("ascii", "replace") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
            fields: dict[str, list[str]] = {}
            files: list[tuple[str, bytes, str]] = []
            allowed_ext = {".log", ".txt", ".gz"}
            for part in message.iter_parts():
                name = part.get_param("name", header="content-disposition") or ""
                filename = part.get_filename()
                payload = part.get_payload(decode=True) or b""
                if filename is not None:
                    safe_name = Path(filename.replace("\\", "/")).name
                    if not safe_name or Path(safe_name).suffix.lower() not in allowed_ext:
                        raise ValueError("Unsupported file type. Use .log, .txt or .gz.")
                    m = re.search(r"(\d+)$", name)
                    files.append((m.group(1) if m else "0", payload, safe_name))
                else:
                    value = payload.decode(part.get_content_charset() or "utf-8")
                    fields.setdefault(name, []).append(value)
            if not files:
                raise ValueError("Choose at least one supported log file.")
            case_id = "CASE-" + uuid.uuid4().hex[:12]
            case = Case.open(self.cases_root / case_id, create=True)
            meta = case.load_meta()
            meta["case_id"] = case_id
            meta["case_name"] = ((fields.get("case_name") or ["Untitled investigation"])[0].strip()[:100] or "Untitled investigation")
            case.save_meta(meta)
            with tempfile.TemporaryDirectory(prefix="tracefuse-upload-") as tmp:
                temp_root = Path(tmp)
                for idx, payload, filename in files:
                    if not payload:
                        raise ValueError(f"{filename} is empty.")
                    source_type = (fields.get("type_" + idx) or [""])[0].lower()
                    if source_type not in SOURCE_TYPES:
                        raise ValueError(f"Choose a log format for {filename}.")
                    tz = (fields.get("tz_" + idx) or [""])[0].strip() or None
                    host = (fields.get("host_" + idx) or [""])[0].strip() or None
                    temp_file = temp_root / filename
                    temp_file.write_bytes(payload)
                    collect(case, temp_file, source_type, tz=tz, host=host, actor="tracefuse-web-upload", note="Uploaded through TRACEFUSE web interface.")
            build_timeline(case, actor="tracefuse-web-upload")
            self.send_response(303)
            self.send_header("Location", f"/case/{case_id}")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        except (ValueError, EvidenceError) as exc:
            self._fail(400, str(exc))
        except Exception as exc:
            print(f"TRACEFUSE upload error: {type(exc).__name__}: {exc}", file=sys.stderr)
            self._fail(500, "Upload could not be processed. Check the local server log for details.")

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        url = urlsplit(self.path)
        params = parse_qs(url.query, keep_blank_values=True)
        try:
            if url.path in ("/", "/index.html"):
                html_name = "welcome.html" if self.app_mode else "dashboard.html"
                html_path = Path(__file__).with_name(html_name)
                self._send(200, html_path.read_bytes(), "text/html; charset=utf-8")
                return
            if url.path == "/welcome.css":
                self._send(200, Path(__file__).with_name("welcome.css").read_bytes(), "text/css; charset=utf-8")
                return
            if self.app_mode and url.path == "/upload":
                self.do_POST()
                return
            if self.app_mode and url.path == "/engine-test":
                html_path = Path(__file__).with_name("engine_test.html")
                if not html_path.is_file():
                    self.send_response(303); self.send_header("Location", "/demo"); self.end_headers(); return
                self._send(200, html_path.read_bytes(), "text/html; charset=utf-8")
                return
            case_match = re.match(r"^/case/(CASE-[a-f0-9]{12})/?$", url.path)
            if case_match:
                case_id = case_match.group(1)
                case_dir = (
    resolve_app_case(self.cases_root, case_id)
    if self.cases_root
    else Path("/")
)
                if not self.app_mode or case_dir.parent != self.cases_root.resolve() or not (case_dir / "case.json").is_file():
                    self._fail(404, "Investigation not found"); return
                html_path = Path(__file__).with_name("dashboard.html")
                case_script = '<script>window.TRACEFUSE_CASE_ID="' + case_id + '";(()=>{const f=window.fetch.bind(window);window.fetch=(input,init)=>{try{const target=(typeof input==="string"||input instanceof URL)?input.toString():input.url;const u=new URL(target,location.origin);if(u.origin===location.origin&&(u.pathname.startsWith("/api/")||u.pathname.startsWith("/export/"))&&!u.searchParams.has("case"))u.searchParams.set("case",window.TRACEFUSE_CASE_ID);return f(u.toString(),init)}catch(e){return f(input,init)}}})();</script>'
                html = html_path.read_text(encoding="utf-8").replace("</head>", case_script + "\n</head>")
                self._send(200, html.encode("utf-8"), "text/html; charset=utf-8"); return
            if self.app_mode and url.path == "/demo":
                from .scenarios import create_demo_cases
                results = create_demo_cases(self.cases_root / "demo-scenarios")
                cards = []
                for result in results:
                    demo_id = "CASE-" + uuid.uuid5(
                        uuid.NAMESPACE_URL, result["scenario_id"]
                    ).hex[:12]

                    # Use the generated demo case directly; do not copy evidence files.
                    cards.append((
                        demo_id,
                        result["title"],
                        bool(result["passed"]),
                    ))
                cards_html = "".join('<a class="scenario" href="/case/{}"><span class="num">SYNTHETIC SCENARIO</span><strong>{}</strong><span class="status">{}</span></a>'.format(cid, title, "Validation passed" if passed else "Validation needs review") for cid,title,passed in cards)
                page = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Choose a demo case · TRACEFUSE</title><link rel="stylesheet" href="/welcome.css"></head><body class="demo-page"><main class="wrap"><a class="brand" href="/">◈ TRACEFUSE</a><p class="eyebrow">CONTROLLED DEMONSTRATION DATA</p><h1>Choose a scenario.</h1><p class="lede">These incidents are synthetic and isolated from uploaded investigations.</p><div class="scenario-grid">' + cards_html + '</div><a class="back" href="/">← Back to home</a></main></body></html>'
                self._send(200, page.encode(), "text/html; charset=utf-8"); return
            if url.path in ("/engine-test", "/engine-test/"):
                html_path = Path(__file__).with_name("engine_test.html")
                if not html_path.is_file():
                    raise FileNotFoundError("engine_test.html is missing from the incident_timeline package")
                self._send(200, html_path.read_bytes(), "text/html; charset=utf-8")
                return
            if url.path == "/api/benchmark/scenarios":
                from .scenarios import SCENARIOS
                catalog = [{
                    "scenario_id": scenario_id,
                    "title": spec["title"],
                    "description": spec["description"],
                    "host": spec["host"],
                    "input_files": list(spec["logs"]),
                    "source_count": len(spec["logs"]),
                    "expected_event_count": spec["expected"]["event_count"],
                    "expected_actions": spec["expected"]["ordered_actions"],
                    "required_indicator_count": len(spec["expected"].get("must_include", [])),
                    "expected_http_statuses": spec["expected"].get("http_statuses"),
                    "synthetic_data": True,
                } for scenario_id, spec in SCENARIOS.items()]
                self._send(200, _json_bytes({
                    "synthetic_data": True,
                    "important": "These are controlled synthetic scenarios, not real incident evidence.",
                    "scenarios": catalog,
                }))
                return
            if url.path == "/api/summary":
                self._send(200, _json_bytes(self._summary()))
                return
            if url.path == "/api/time-analysis":
                # Read-only diagnostics. Clock-offset previews are computed in memory;
                # this endpoint never updates case metadata, normalized events, or custody.
                try:
                    limit = min(max(int((params.get("limit") or ["100"])[0]), 1), 200)
                    offset = max(int((params.get("offset") or ["0"])[0]), 0)
                except ValueError as exc:
                    raise ValueError("limit and offset must be integers") from exc
                source_filter = (params.get("source_id") or [""])[0] or None
                issues_only_text = (params.get("issues_only") or ["0"])[0].strip().lower()
                if issues_only_text not in ("0", "1", "true", "false", "yes", "no"):
                    raise ValueError("issues_only must be a boolean value")
                issues_only = issues_only_text in ("1", "true", "yes")
                preview_source_id = (params.get("preview_source_id") or [""])[0] or None
                preview_offset_text = (params.get("preview_offset_s") or [""])[0]
                preview_offset_s = None
                if preview_offset_text != "":
                    try:
                        preview_offset_s = float(preview_offset_text)
                    except ValueError as exc:
                        raise ValueError("preview_offset_s must be a finite number") from exc
                event_path = self.case.output_dir / "events.jsonl"
                if not event_path.is_file():
                    self._events()  # raise the standard, actionable missing-timeline error
                report = build_time_analysis(
                    self.case, list(load_events(event_path)), limit=limit, offset=offset,
                    source_filter=source_filter, issues_only=issues_only,
                    preview_source_id=preview_source_id, preview_offset_s=preview_offset_s,
                )
                self._send(200, _json_bytes(report))
                return
            if url.path == "/api/benchmark":
                # Runs use disposable synthetic case folders. Never touch the active case.
                from .scenarios import SCENARIOS, create_demo_cases
                scenario_filter = (params.get("scenario") or [""])[0].strip()
                if scenario_filter and scenario_filter not in SCENARIOS:
                    raise ValueError(f"unknown scenario_id: {scenario_filter}")
                selected = [scenario_filter] if scenario_filter else None
                with tempfile.TemporaryDirectory(prefix="tracefuse-benchmark-") as tmp_dir:
                    results = create_demo_cases(Path(tmp_dir) / "scenarios", scenario_ids=selected)
                scenarios = []
                for result in results:
                    spec = SCENARIOS[result["scenario_id"]]
                    scenarios.append({
                        "scenario_id": result["scenario_id"],
                        "title": result["title"],
                        "description": result["description"],
                        "host": result["host"],
                        "input_files": result["input_files"],
                        "source_count": result["source_count"],
                        "expected_event_count": result["expected_event_count"],
                        "events": result["event_count"],
                        "gaps": result["gap_count"],
                        "tracefuse_pipeline_ms": result["tracefuse_elapsed_ms"],
                        "integrity_ok": result["integrity_ok"],
                        "checks": result["checks"],
                        "expected_action_counts": result["expected_action_counts"],
                        "actual_action_counts": result["actual_action_counts"],
                        "expected_timeline": result["expected_timeline"],
                        "actual_timeline": result["actual_timeline"],
                        "passed": result["passed"],
                        "synthetic_data": True,
                    })
                self._send(200, _json_bytes({
                    "scope": "single-scenario" if scenario_filter else "full-suite",
                    "method": "Per-case wall-clock measurement from synthetic input preparation and evidence collection/hash through normalized timeline construction. Expected-output and integrity validation run after the timed processing interval.",
                    "note": "Machine processing time is not human triage time. The run uses temporary synthetic cases and does not alter the active investigation or its evidence.",
                    "scenarios": scenarios,
                }))
                return
            if url.path == "/api/cases":
                roots = self.case_roots or discover_cases(self.cases_root or self.case_root)
                self._send(200, _json_bytes({"cases": [{"id": name, "path": str(path)} for name, path in roots.items()]}))
                return
            if url.path == "/api/insights":
                events = self._events()
                findings = detect_findings(events)
                activity = [{"ts_utc": e.get("ts_utc"), "count": 1, "event_id": e.get("event_id"), "action": e.get("action")} for e in events]
                self._send(200, _json_bytes({"findings": findings, "entities": summarize_entities(events), "activity": {"points": activity, "sampled": False}}))
                return
            if url.path == "/api/custody":
                records = self.case.read_custody()
                chain_errors = verify_chain(self.case)
                previous = "0" * 64
                rendered = []
                from .evidence import _record_hash
                for i, record in enumerate(records, start=1):
                    errors = []
                    if record.get("seq") != i: errors.append("sequence number mismatch")
                    if record.get("prev_sha256") != previous: errors.append("link to previous record is broken")
                    if _record_hash(record) != record.get("record_sha256"): errors.append("contents do not match its hash")
                    fields = {k: v for k, v in record.items() if k not in {"seq", "ts_utc", "action", "actor", "tool", "prev_sha256", "record_sha256"} and k != "original_path"}
                    rendered.append({"seq": i, "ts_utc": record.get("ts_utc"), "action": record.get("action"), "actor": record.get("actor"), "fields": fields, "ok": not errors, "errors": errors})
                    previous = record.get("record_sha256", "")
                self._send(200, _json_bytes({"chain_ok": not chain_errors, "errors": chain_errors, "records": rendered}))
                return
            if url.path == "/api/gaps":
                try:
                    limit = min(max(int((params.get("limit") or ["100"])[0]), 1), 500)
                    offset = max(int((params.get("offset") or ["0"])[0]), 0)
                except ValueError as exc:
                    raise ValueError("limit and offset must be integers") from exc
                gap_path = self.case.output_dir / "gaps.jsonl"
                gaps = [json.loads(line) for line in gap_path.read_text(encoding="utf-8").splitlines() if line.strip()] if gap_path.is_file() else []
                self._send(200, _json_bytes({"gaps": gaps[offset:offset + limit], "total": len(gaps), "offset": offset, "limit": limit}))
                return
            if url.path == "/api/events":
                all_events = filter_event_dicts(self._events(), self._filters(params))
                requested_ids = (params.get("ids") or [""])[0]
                if requested_ids:
                    wanted = set(requested_ids.split(","))
                    all_events = [e for e in all_events if e.get("event_id") in wanted]
                    all_events.sort(key=lambda e: requested_ids.split(",").index(e.get("event_id")))
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
                requested_ids = (params.get("ids") or [""])[0]
                if requested_ids:
                    wanted = set(requested_ids.split(","))
                    full_events = self._events()
                    full_findings = detect_findings(full_events)
                    report["events"] = [e for e in report["events"] if e.get("event_id") in wanted]
                    report["findings"] = [f for f in full_findings
                                           if wanted.intersection(f.get("event_ids", []))]
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
            status = 400 if "case" in url.query.lower() else 404
            self._fail(status, str(exc))
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


def serve_app(host: str = "127.0.0.1", port: int = 8765, cases_dir: str | Path = "cases/web-app") -> None:
    """Serve the TRACEFUSE onboarding, upload workflow, and case dashboard."""
    root = Path(cases_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    for required in ("welcome.html", "welcome.css", "dashboard.html"):
        if not Path(__file__).with_name(required).is_file():
            raise FileNotFoundError(f"{required} is missing from the incident_timeline package")
    handler_class = type("AppTracefuseHandler", (TracefuseHandler,), {"case_root": root, "cases_root": root, "app_mode": True})
    server = ThreadingHTTPServer((host, port), handler_class)
    actual_host, actual_port = server.server_address[:2]
    display_host = actual_host if actual_host not in ("0.0.0.0", "::") else "127.0.0.1"
    print("TRACEFUSE web application")
    print(f"Open http://{display_host}:{actual_port} in your browser")
    print(f"Case storage: {root}")
    print("Local demo mode. Do not expose this server to untrusted networks.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping TRACEFUSE web application…")
    finally:
        server.server_close()
