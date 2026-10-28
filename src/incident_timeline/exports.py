"""Traceable JSON and PDF exports for an incident case."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from xml.sax.saxutils import escape

from .evidence import Case, EvidenceError, verify
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


def load_case_export(case_path: str | Path, filters: dict[str, str | None] | None = None) -> dict[str, Any]:
    """Load the normalized timeline plus evidence references and integrity status."""
    case = Case.open(case_path)
    events_path = case.output_dir / "events.jsonl"
    if not events_path.is_file():
        raise EvidenceError(f"normalized timeline is missing: {events_path}; run `incident-timeline parse {case.root}` first")

    events = [event.to_dict() for event in load_events(events_path)]
    selected = filter_event_dicts(events, filters)
    summary_path = case.output_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}
    metadata = case.load_meta()
    verification = verify(case, record=False)
    source_by_id = {source["source_id"]: source for source in case.sources()}

    export_events = []
    for event in selected:
        source = source_by_id.get(event.get("source_id"), {})
        output_event = dict(event)
        output_event["evidence_reference"] = {
            "source_id": event.get("source_id"),
            "source_file": event.get("source_file") or source.get("original_name"),
            "line_no": event.get("line_no"),
            "file_sha256": event.get("file_sha256") or source.get("sha256"),
            "evidence_path": source.get("evidence_path"),
        }
        export_events.append(output_event)

    return {
        "schema_version": "1.0",
        "product": "TRACEFUSE",
        "case_id": metadata.get("case_id", case.root.name),
        "generated_utc": to_rfc3339(datetime.now(UTC)),
        "filters": {k: v for k, v in (filters or {}).items() if v not in (None, "")},
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
        "events": export_events,
    }


def export_json(case_path: str | Path, output_path: str | Path, filters: dict[str, str | None] | None = None) -> Path:
    report = load_case_export(case_path, filters)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return destination


def export_pdf(case_path: str | Path, output_path: str | Path, filters: dict[str, str | None] | None = None) -> Path:
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

    report = load_case_export(case_path, filters)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    page = landscape(A4)
    doc = SimpleDocTemplate(
        str(destination), pagesize=page, rightMargin=14 * mm, leftMargin=14 * mm,
        topMargin=15 * mm, bottomMargin=16 * mm, title=f"TRACEFUSE Incident Report - {report['case_id']}",
        author="TRACEFUSE", subject="Evidence-preserving incident reconstruction",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=21,
                              leading=25, textColor=colors.HexColor("#141a16"), alignment=TA_LEFT, spaceAfter=5))
    styles.add(ParagraphStyle(name="SectionHeading", parent=styles["Heading2"], fontSize=12, leading=15,
                              textColor=colors.HexColor("#1f6b45"), spaceBefore=6, spaceAfter=3))
    styles.add(ParagraphStyle(name="SmallText", parent=styles["BodyText"], fontSize=7.5, leading=9))
    styles.add(ParagraphStyle(name="HeadCell", parent=styles["SmallText"], fontName="Helvetica-Bold", textColor=colors.white))
    styles.add(ParagraphStyle(name="TinyText", parent=styles["BodyText"], fontSize=6.5, leading=8, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="Cell", parent=styles["BodyText"], fontSize=7.2, leading=9, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="CellTiny", parent=styles["BodyText"], fontSize=6.1, leading=7.6, wordWrap="CJK"))

    def p(value: Any, style: str = "Cell") -> Paragraph:
        return Paragraph(escape("-" if value is None or value == "" else str(value)), styles[style])

    story = [Paragraph("TRACEFUSE", styles["ReportTitle"]),
             Paragraph("Evidence-preserving incident reconstruction report", styles["SmallText"]),
             Spacer(1, 1 * mm)]
    integrity = report["integrity"]
    status = "VERIFIED - all collected evidence and custody links passed" if integrity["verified"] else "WARNING - integrity verification reported issues"
    overview = [
        [p("Case ID", "SmallText"), p(report["case_id"], "SmallText"), p("Generated (UTC)", "SmallText"), p(report["generated_utc"], "SmallText")],
        [p("Timeline events", "SmallText"), p(len(report["events"]), "SmallText"), p("Sources", "SmallText"), p(len(report["sources"]), "SmallText")],
        [p("Evidence integrity", "SmallText"), p(status, "SmallText"), p("Filters", "SmallText"), p(json.dumps(report["filters"], ensure_ascii=False) or "None", "SmallText")],
    ]
    overview_table = Table(overview, colWidths=[27 * mm, 75 * mm, 28 * mm, 125 * mm])
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ef")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#eef2ef")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d3dbd5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.extend([overview_table, Paragraph("Evidence sources", styles["SectionHeading"])])

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
    source_table = LongTable(source_rows, colWidths=[20 * mm, 38 * mm, 60 * mm, 137 * mm], repeatRows=1)
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
        canvas.drawString(14 * mm, 7 * mm, f"TRACEFUSE | Case {report['case_id']} | Generated {report['generated_utc']}")
        canvas.drawRightString(page[0] - 14 * mm, 7 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return destination


def safe_case_filename(case_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", case_id).strip("._-") or "case"
