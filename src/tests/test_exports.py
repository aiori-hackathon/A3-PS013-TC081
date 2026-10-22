from __future__ import annotations

import json
from pathlib import Path

from incident_timeline.exports import export_json, export_pdf
from incident_timeline.scenarios import create_demo_cases


def _case(tmp_path: Path) -> Path:
    create_demo_cases(tmp_path / "demos")
    return tmp_path / "demos" / "01-brute-force-to-sudo" / "case"


def test_json_export_contains_traceable_evidence_references(tmp_path: Path) -> None:
    case_path = _case(tmp_path)
    output = export_json(case_path, tmp_path / "exports" / "timeline.json")
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["product"] == "TRACEFUSE"
    assert report["integrity"]["verified"] is True
    assert len(report["events"]) == 6
    event = report["events"][0]
    ref = event["evidence_reference"]
    assert ref["source_id"] == event["source_id"]
    assert ref["line_no"] == event["line_no"]
    assert len(ref["file_sha256"]) == 64
    assert event["raw_line"]


def test_json_and_pdf_exports_honor_action_filter(tmp_path: Path) -> None:
    case_path = _case(tmp_path)
    filters = {"action": "sudo_command"}
    output_json = export_json(case_path, tmp_path / "sudo.json", filters)
    output_pdf = export_pdf(case_path, tmp_path / "sudo.pdf", filters)
    report = json.loads(output_json.read_text(encoding="utf-8"))
    assert len(report["events"]) == 1
    assert all(event["action"] == "sudo_command" for event in report["events"])
    content = output_pdf.read_bytes()
    assert content.startswith(b"%PDF-")
    assert len(content) > 1200
