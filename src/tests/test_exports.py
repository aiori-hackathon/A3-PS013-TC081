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
    assert report["product"] == "ORISECT"
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


def test_exports_carry_findings_with_line_and_hash_citations(tmp_path: Path) -> None:
    case_path = _case(tmp_path)
    report = json.loads(export_json(case_path, tmp_path / "all.json").read_text(encoding="utf-8"))
    assert report["findings"], "the scenario raises findings"
    by_id = {e["event_id"]: e for e in report["events"]}
    for finding in report["findings"]:
        assert [ref["event_id"] for ref in finding["evidence"]] == finding["event_ids"]
        for ref in finding["evidence"]:
            assert ref["file_sha256"] == by_id[ref["event_id"]]["file_sha256"]
            assert ref["raw_line"] == by_id[ref["event_id"]]["raw_line"]

    # Scoped to one finding's evidence, both exports keep only that finding's lines.
    first = report["findings"][0]
    scoped = json.loads(export_json(case_path, tmp_path / "one.json", event_ids=first["event_ids"]).read_text())
    assert sorted(e["event_id"] for e in scoped["events"]) == sorted(first["event_ids"])
    assert scoped["scope"] == {"event_ids": sorted(first["event_ids"])}
    assert first["id"] in {f["id"] for f in scoped["findings"]}
    assert export_pdf(case_path, tmp_path / "one.pdf", event_ids=first["event_ids"]).read_bytes().startswith(b"%PDF-")
