"""Traceable JSON and PDF exports for an incident case."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from xml.sax.saxutils import escape

from .evidence import Case, EvidenceError, verify
from .findings import SEVERITY_ORDER, detect
from .models import load_events
from .timeutil import UTC, to_rfc3339


def _parse_filter_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp filter: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _draw_brand(canvas: Any, x: float, top: float, height: float, ink: Any, accent: Any) -> None:
    """Draw the ORISECT mark and wordmark (from brand/*.svg) as vector paths.

    Geometry is in the SVGs' design units with y pointing down; ``height`` is
    the mark height in points. PDF angles run the other way, so arcs negate.
    """
    k = height / 700.0                      # mark design box is 700 units high
    X = lambda dx: x + (dx + 12) * k        # mark viewBox starts at x = -12, y = 30
    Y = lambda dy: top - (dy - 30) * k

    def box(cx: float, cy: float, rx: float, ry: float) -> tuple[float, float, float, float]:
        return X(cx - rx), Y(cy + ry), X(cx + rx), Y(cy - ry)

    canvas.saveState()
    canvas.setFillColor(ink)
    left = canvas.beginPath()
    left.moveTo(X(325), Y(160))
    left.arcTo(*box(325, 415, 255, 255), startAng=90, extent=146.7)
    left.lineTo(X(325), Y(720))
    left.lineTo(X(325), Y(595))
    left.arcTo(*box(325, 425, 145, 170), startAng=270, extent=-180)
    left.close()
    right = canvas.beginPath()
    right.moveTo(X(352), Y(40))
    right.lineTo(X(475.7), Y(109.3))
    right.arcTo(*box(352, 330, 253, 253), startAng=60.8, extent=-120.9)
    right.lineTo(X(478), Y(150))
    right.lineTo(X(352), Y(150))
    right.close()
    canvas.drawPath(left, stroke=0, fill=1)
    canvas.drawPath(right, stroke=0, fill=1)
    canvas.setFillColor(accent)
    blade = canvas.beginPath()
    for i, (bx, by) in enumerate(((325, 255), (418, 340), (418, 665), (325, 580))):
        (blade.lineTo if i else blade.moveTo)(X(bx), Y(by))
    blade.close()
    canvas.drawPath(blade, stroke=0, fill=1)

    # Wordmark: geometric strokes, cap height 44 units, vertically centred on the mark.
    w = height * 0.36 / 44.0
    wx0 = x + height * 1.08
    wy0 = top - height * 0.32
    WX = lambda dx: wx0 + dx * w
    WY = lambda dy: wy0 - dy * w

    def arc_box(cx: float, cy: float, r: float) -> tuple[float, float, float, float]:
        return WX(cx - r), WY(cy + r), WX(cx + r), WY(cy - r)

    canvas.setStrokeColor(ink)
    canvas.setLineWidth(5.5 * w)
    canvas.setLineCap(0)
    canvas.circle(WX(22), WY(22), 19.5 * w, stroke=1, fill=0)                       # O
    r_ = canvas.beginPath()                                                          # R
    r_.moveTo(WX(72.5), WY(44)); r_.lineTo(WX(72.5), WY(2.5)); r_.lineTo(WX(88), WY(2.5))
    r_.arcTo(*arc_box(88, 13, 10.5), startAng=90, extent=-180)
    r_.lineTo(WX(72.5), WY(23.5))
    r_.moveTo(WX(90), WY(27)); r_.lineTo(WX(104), WY(44))
    canvas.drawPath(r_, stroke=1, fill=0)
    canvas.line(WX(132.5), WY(0), WX(132.5), WY(44))                                 # I
    s_ = canvas.beginPath()                                                          # S
    s_.moveTo(WX(200), WY(2.5)); s_.lineTo(WX(170.25), WY(2.5))
    s_.arcTo(*arc_box(170.25, 12.25, 9.75), startAng=90, extent=180)
    s_.lineTo(WX(189.75), WY(22))
    s_.arcTo(*arc_box(189.75, 31.75, 9.75), startAng=90, extent=-180)
    s_.lineTo(WX(160), WY(41.5))
    canvas.drawPath(s_, stroke=1, fill=0)
    canvas.line(WX(226), WY(2.5), WX(260), WY(2.5))                                  # E outer bars
    canvas.line(WX(226), WY(41.5), WX(260), WY(41.5))
    c_ = canvas.beginPath()                                                          # C
    c_.moveTo(WX(326), WY(2.5)); c_.lineTo(WX(308), WY(2.5))
    c_.arcTo(*arc_box(308, 22, 19.5), startAng=90, extent=180)
    c_.lineTo(WX(326), WY(41.5))
    canvas.drawPath(c_, stroke=1, fill=0)
    canvas.line(WX(352), WY(2.5), WX(392), WY(2.5))                                  # T
    canvas.line(WX(372), WY(2.5), WX(372), WY(44))
    canvas.setStrokeColor(accent)
    canvas.line(WX(226), WY(22), WX(260), WY(22))                                    # E middle bar
    canvas.restoreState()


FINDING_EVIDENCE_LIMIT = 6
FINDING_RAW_LIMIT = 400  # long enough for a firewall line's addresses and byte counts
SEVERITY_INK = {"high": "#b3261e", "medium": "#8a5a00", "info": "#4d5a52"}


def _short_hash(digest: str | None) -> str:
    return f"{digest[:8]}…{digest[-8:]}" if digest and len(digest) > 16 else (digest or "-")


def _findings_story(findings: list[dict[str, Any]], styles: Any, colors: Any, mm: float,
                    Paragraph: Any, LongTable: Any, TableStyle: Any) -> list[Any]:
    """The report's findings table: each lead with the lines and file hashes behind it."""
    story: list[Any] = [Paragraph("Findings", styles["SectionHeading"])]
    if not findings:
        story.append(Paragraph("No rule fired on the exported events. That does not mean nothing happened; "
                               "review the timeline below.", styles["SmallText"]))
        return story

    def cell(text: Any) -> str:
        return escape("-" if text in (None, "") else str(text))

    rows = [[Paragraph(h, styles["HeadCell"]) for h in ("Severity", "Finding", "When (UTC)", "Evidence cited")]]
    for f in findings:
        ink = SEVERITY_INK.get(f["severity"], SEVERITY_INK["info"])
        technique = f"ATT&amp;CK {cell(f['technique'])} · {cell(f['technique_name'])}<br/>" if f.get("technique") else ""
        body = (f"<b>{cell(f['title'])}</b><br/>{cell(f['summary'])}<br/>"
                f"<font color='#5a665e'>{technique}Rule <i>{cell(f['rule'])}</i>: {cell(f['rationale'])}</font>")
        first, last = f.get("first_ts_utc"), f.get("last_ts_utc")
        when = cell(first) if first == last else f"{cell(first)}<br/>to {cell(last)}"
        cites = []
        for ref in f["evidence"][:FINDING_EVIDENCE_LIMIT]:
            raw = str(ref.get("raw_line") or "")
            raw = raw if len(raw) <= FINDING_RAW_LIMIT else raw[:FINDING_RAW_LIMIT - 1] + "…"
            cites.append(f"<b>{cell(ref['source_id'])}:{cell(ref['line_no'])}</b> {cell(ref['source_file'])} · "
                         f"SHA-256 {cell(_short_hash(ref.get('file_sha256')))}<br/>"
                         f"<font face='Courier' size='5.6'>{cell(raw)}</font>")
        extra = len(f["evidence"]) - FINDING_EVIDENCE_LIMIT
        if extra > 0:
            cites.append(f"<i>and {extra} more line{'s' if extra != 1 else ''}: "
                         f"{cell(', '.join(r['event_id'] for r in f['evidence'][FINDING_EVIDENCE_LIMIT:]))}</i>")
        rows.append([
            Paragraph(f"<font color='{ink}'><b>{cell(f['severity'].capitalize())}</b></font>", styles["Cell"]),
            Paragraph(body, styles["Cell"]),
            Paragraph(when, styles["CellTiny"]),
            Paragraph("<br/>".join(cites) or "-", styles["CellTiny"]),
        ])
    table = LongTable(rows, colWidths=[17 * mm, 92 * mm, 34 * mm, 112 * mm], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e2a22")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d3dbd5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8f6")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(table)
    story.append(Paragraph("Full SHA-256 values are listed under Evidence sources. Every finding's complete "
                           "list of evidence lines is in the JSON export.", styles["TinyText"]))
    return story


def filter_event_dicts(events: Iterable[dict[str, Any]], filters: dict[str, str | None] | None = None) -> list[dict[str, Any]]:
    """Apply the same filters in the web viewer and in exported reports."""
    filters = filters or {}
    query = (filters.get("q") or "").strip().casefold()
    source_id = (filters.get("source") or "").strip()
    action = (filters.get("action") or "").strip()
    outcome = (filters.get("outcome") or "").strip()
    start = _parse_filter_time(filters.get("start"))
    end = _parse_filter_time(filters.get("end"))
    selected = []

    for event in events:
        if source_id and event.get("source_id") != source_id:
            continue
        if action and event.get("action") != action:
            continue
        if outcome and event.get("outcome") != outcome:
            continue
        try:
            stamp = _parse_filter_time(str(event.get("ts_utc") or ""))
        except ValueError:
            stamp = None
        if start and (stamp is None or stamp < start):
            continue
        if end and (stamp is None or stamp > end):
            continue
        if query:
            searchable = " ".join(
                str(event.get(key) or "")
                for key in ("event_id", "ts_utc", "source_id", "source_type", "source_file", "file_sha256", "host",
                            "process", "user", "src_ip", "action", "outcome", "message", "raw_line", "extra")
            ).casefold()
            if query not in searchable:
                continue
        selected.append(event)

    def sort_key(event: dict[str, Any]) -> tuple[datetime, str, int]:
        try:
            timestamp = _parse_filter_time(str(event.get("ts_utc") or ""))
        except ValueError:
            timestamp = None
        return (timestamp or datetime.min.replace(tzinfo=UTC), str(event.get("source_id") or ""), int(event.get("line_no") or 0))

    selected.sort(key=sort_key)
    return selected


def _evidence_reference(event: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_id": event.get("source_id"),
        "source_file": event.get("source_file") or source.get("original_name"),
        "line_no": event.get("line_no"),
        "file_sha256": event.get("file_sha256") or source.get("sha256"),
        "evidence_path": source.get("evidence_path"),
    }


def load_case_export(case_path: str | Path, filters: dict[str, str | None] | None = None,
                     event_ids: Iterable[str] | None = None) -> dict[str, Any]:
    """Load the normalized timeline plus evidence references and integrity status.

    Findings are always computed over the whole timeline, because rules need
    the surrounding events; a filtered export keeps the findings that cite at
    least one exported event. ``event_ids`` narrows the export to those events
    (a finding's evidence) after the filters.
    """
    case = Case.open(case_path)
    events_path = case.output_dir / "events.jsonl"
    if not events_path.is_file():
        raise EvidenceError(f"normalized timeline is missing: {events_path}; run `incident-timeline parse {case.root}` first")

    events = [event.to_dict() for event in load_events(events_path)]
    selected = filter_event_dicts(events, filters)
    scoped = event_ids is not None
    if scoped:
        wanted = set(event_ids)
        selected = [e for e in selected if e.get("event_id") in wanted]
    summary_path = case.output_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}
    metadata = case.load_meta()
    verification = verify(case, record=False)
    source_by_id = {source["source_id"]: source for source in case.sources()}

    export_events = []
    for event in selected:
        source = source_by_id.get(event.get("source_id"), {})
        output_event = dict(event)
        output_event["evidence_reference"] = _evidence_reference(event, source)
        export_events.append(output_event)

    by_id = {e["event_id"]: e for e in events}
    exported_ids = {e["event_id"] for e in selected}
    narrowed = scoped or any(v not in (None, "") for v in (filters or {}).values())
    findings = []
    for finding in detect(events):
        if narrowed and not exported_ids.intersection(finding["event_ids"]):
            continue
        cited = [by_id[i] for i in finding["event_ids"] if i in by_id]
        findings.append({**finding, "evidence": [
            {**_evidence_reference(e, source_by_id.get(e.get("source_id"), {})), "event_id": e["event_id"],
             "ts_utc": e.get("ts_utc"), "raw_line": e.get("raw_line")}
            for e in cited
        ]})

    return {
        "schema_version": "1.0",
        "product": "ORISECT",
        "case_id": metadata.get("case_id", case.root.name),
        "generated_utc": to_rfc3339(datetime.now(UTC)),
        "filters": {k: v for k, v in (filters or {}).items() if v not in (None, "")},
        "scope": {"event_ids": sorted(exported_ids)} if scoped else None,
        "integrity": {
            "verified": verification.ok,
            "files_ok": verification.files_ok,
            "files_bad": verification.files_bad,
            "chain_errors": verification.chain_errors,
            "issues": verification.files_bad + verification.chain_errors,
        },
        "summary": summary,
        "sources": [
            {
                "source_id": source.get("source_id"),
                "source_type": source.get("source_type"),
                "source_file": source.get("original_name"),
                "sha256": source.get("sha256"),
                "host": source.get("host"),
                "timezone": source.get("tz"),
                "skew_offset_s": source.get("skew_offset_s") or 0.0,
            }
            for source in case.sources()
        ],
        "findings": findings,
        "events": export_events,
    }


def export_json(case_path: str | Path, output_path: str | Path, filters: dict[str, str | None] | None = None,
                event_ids: Iterable[str] | None = None) -> Path:
    report = load_case_export(case_path, filters, event_ids)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return destination


def export_pdf(case_path: str | Path, output_path: str | Path, filters: dict[str, str | None] | None = None,
               event_ids: Iterable[str] | None = None) -> Path:
    """Write a paginated, evidence-referenced PDF report using ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, LongTable
    except ImportError as exc:  # a useful error if users installed the old engine without report deps
        raise RuntimeError("PDF export requires ReportLab. Install project dependencies with `pip install -r requirements.txt`.") from exc

    report = load_case_export(case_path, filters, event_ids)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    page = landscape(A4)
    doc = SimpleDocTemplate(
        str(destination), pagesize=page, rightMargin=14 * mm, leftMargin=14 * mm,
        topMargin=15 * mm, bottomMargin=16 * mm, title=f"ORISECT Incident Report - {report['case_id']}",
        author="ORISECT", subject="Evidence-preserving incident reconstruction",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SectionHeading", parent=styles["Heading2"], fontSize=12, leading=15,
                              textColor=colors.HexColor("#1f6b45"), spaceBefore=6, spaceAfter=3))
    styles.add(ParagraphStyle(name="SmallText", parent=styles["BodyText"], fontSize=7.5, leading=9))
    styles.add(ParagraphStyle(name="HeadCell", parent=styles["SmallText"], fontName="Helvetica-Bold", textColor=colors.white))
    styles.add(ParagraphStyle(name="TinyText", parent=styles["BodyText"], fontSize=6.5, leading=8, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="Cell", parent=styles["BodyText"], fontSize=7.2, leading=9, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="CellTiny", parent=styles["BodyText"], fontSize=6.1, leading=7.6, wordWrap="CJK"))

    def p(value: Any, style: str = "Cell") -> Paragraph:
        return Paragraph(escape("-" if value is None or value == "" else str(value)), styles[style])

    story = [Spacer(1, 10 * mm),
             Paragraph("Evidence-preserving incident reconstruction report", styles["SmallText"]),
             Spacer(1, 1 * mm)]
    integrity = report["integrity"]
    status = "VERIFIED - all collected evidence and custody links passed" if integrity["verified"] else "WARNING - integrity verification reported issues"
    findings = report["findings"]
    severity_counts = {sev: sum(f["severity"] == sev for f in findings) for sev in SEVERITY_ORDER}
    findings_text = (f"{len(findings)} ({', '.join(f'{n} {sev}' for sev, n in severity_counts.items() if n)})"
                     if findings else "No rule fired on the exported events")
    scope_text = json.dumps(report["filters"], ensure_ascii=False) if report["filters"] else "None"
    if report.get("scope"):
        scope_text += f"; limited to {len(report['scope']['event_ids'])} selected evidence lines"
    overview = [
        [p("Case ID", "SmallText"), p(report["case_id"], "SmallText"), p("Generated (UTC)", "SmallText"), p(report["generated_utc"], "SmallText")],
        [p("Timeline events", "SmallText"), p(len(report["events"]), "SmallText"), p("Sources", "SmallText"), p(len(report["sources"]), "SmallText")],
        [p("Evidence integrity", "SmallText"), p(status, "SmallText"), p("Filters", "SmallText"), p(scope_text, "SmallText")],
        [p("Findings", "SmallText"), p(findings_text, "SmallText"), p("Method", "SmallText"),
         p("Findings come from fixed, readable rules over the whole timeline. Each cites its evidence lines by "
           "source:line and the SHA-256 of the file they were read from. They are leads to verify, not conclusions.", "SmallText")],
    ]
    overview_table = Table(overview, colWidths=[27 * mm, 75 * mm, 28 * mm, 125 * mm], hAlign="LEFT")
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ef")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#eef2ef")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d3dbd5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(overview_table)
    story.extend(_findings_story(findings, styles, colors, mm, Paragraph, LongTable, TableStyle))
    story.append(Paragraph("Evidence sources", styles["SectionHeading"]))

    source_rows = [[p("Source", "HeadCell"), p("Type / host", "HeadCell"), p("File", "HeadCell"), p("SHA-256", "HeadCell")]]
    for source in report["sources"]:
        source_rows.append([
            p(source.get("source_id"), "TinyText"),
            p(f"{source.get('source_type') or '-'} / {source.get('host') or '-'}", "TinyText"),
            p(source.get("source_file"), "TinyText"),
            p(source.get("sha256"), "TinyText"),
        ])
    if len(source_rows) == 1:
        source_rows.append([p("No sources"), p("-"), p("-"), p("-")])
    source_table = LongTable(source_rows, colWidths=[20 * mm, 38 * mm, 60 * mm, 137 * mm], repeatRows=1, hAlign="LEFT")
    source_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e2a22")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d3dbd5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.extend([source_table, Paragraph("Incident timeline", styles["SectionHeading"])])

    timeline_rows = [[p("Time (UTC)", "HeadCell"), p("Action / outcome", "HeadCell"), p("Actor / source IP", "HeadCell"),
                     p("Evidence reference", "HeadCell"), p("Event details and original line", "HeadCell")]]
    for event in report["events"]:
        ref = event["evidence_reference"]
        who = " / ".join(str(v) for v in (event.get("user"), event.get("src_ip")) if v) or "-"
        details = f"<b>Message:</b> {escape(str(event.get('message') or '-'))}<br/><b>Raw line:</b> {escape(str(event.get('raw_line') or '-'))}"
        # The source inventory above records each full SHA-256 once. Each event
        # points to the exact source ID and line number, avoiding redundant hashes
        # that would otherwise dominate the compact timeline table.
        ref_txt = (f"{escape(str(ref.get('source_id') or '-'))}:{escape(str(ref.get('line_no') or '-'))} · "
                   f"{escape(str(ref.get('source_file') or '-'))}<br/>Full SHA-256: see source inventory")
        action_txt = f"{escape(str(event.get('action') or '-'))}<br/>Outcome: {escape(str(event.get('outcome') or 'unknown'))}"
        timeline_rows.append([
            p(event.get("ts_utc"), "CellTiny"),
            Paragraph(action_txt, styles["CellTiny"]),
            p(who, "CellTiny"), Paragraph(ref_txt, styles["CellTiny"]), Paragraph(details, styles["CellTiny"]),
        ])
    if len(timeline_rows) == 1:
        timeline_rows.append([p("No events matched the selected filters", "Cell"), p(""), p(""), p(""), p("")])
    timeline_table = LongTable(timeline_rows, colWidths=[37 * mm, 36 * mm, 36 * mm, 74 * mm, 72 * mm], repeatRows=1, hAlign="LEFT")
    timeline_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e2a22")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d3dbd5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8f6")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(timeline_table)
    if integrity["issues"]:
        story.append(Paragraph("Integrity verification issues", styles["SectionHeading"]))
        story.extend(Paragraph(escape(str(issue)), styles["SmallText"]) for issue in integrity["issues"])

    def footer(canvas: Any, document: Any) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#d3dbd5"))
        canvas.line(14 * mm, 11 * mm, page[0] - 14 * mm, 11 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#5a665e"))
        canvas.drawString(14 * mm, 7 * mm, f"ORISECT | Case {report['case_id']} | Generated {report['generated_utc']}")
        canvas.drawRightString(page[0] - 14 * mm, 7 * mm, f"Page {document.page}")
        canvas.restoreState()

    def first_page(canvas: Any, document: Any) -> None:
        _draw_brand(canvas, 14 * mm, page[1] - 12 * mm, 11 * mm, colors.HexColor("#1e2622"), colors.HexColor("#1f8a55"))
        footer(canvas, document)

    doc.build(story, onFirstPage=first_page, onLaterPages=footer)
    return destination


def safe_case_filename(case_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", case_id).strip("._-") or "case"
