from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import urlopen

from incident_timeline.scenarios import create_demo_cases
from incident_timeline.web import TracefuseHandler


def _serve(case_path: Path):
    handler = type("TimeAnalysisHandler", (TracefuseHandler,), {"case_root": case_path.resolve()})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


def _get(url: str) -> dict:
    with urlopen(url) as response:
        return json.loads(response.read())


def _case(tmp_path: Path, scenario: str = "02-web-exploit-to-server-access") -> Path:
    create_demo_cases(tmp_path / "demos")
    return tmp_path / "demos" / scenario / "case"


def test_time_analysis_exposes_recorded_timestamp_basis_not_confidence_scores(tmp_path: Path) -> None:
    case_path = _case(tmp_path)
    server, thread, base = _serve(case_path)
    try:
        data = _get(base + "/api/time-analysis?limit=20")
        assert data["summary"]["event_count"] == 8
        assert data["summary"]["source_count"] == 2
        assert "events_flagged_for_time_review" in data["summary"]
        assert "exact_cross_source_timestamp_tie_groups" in data["summary"]
        assert "confidence_score" not in data
        assert len(data["sources"]) == 2
        assert data["events"]
        event = data["events"][0]
        assert event["raw_timestamp"]
        assert event["interpreted_source_utc"].endswith("Z")
        assert event["normalized_utc"].endswith("Z")
        assert event["timestamp_precision_s"] > 0
        assert "current_rank" in event and "preview_rank" in event
        assert data["preview"] is None
        assert data["pagination"]["filtered_total"] == 8
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_offset_preview_is_read_only_and_reports_order_changes(tmp_path: Path) -> None:
    case_path = _case(tmp_path)
    event_path = case_path / "normalised" / "events.jsonl"
    before = {
        "case": (case_path / "case.json").read_bytes(),
        "events": event_path.read_bytes(),
        "custody": (case_path / "custody.jsonl").read_bytes(),
    }
    server, thread, base = _serve(case_path)
    try:
        params = urlencode({"preview_source_id": "S002", "preview_offset_s": "3600", "limit": "100"})
        result = _get(base + "/api/time-analysis?" + params)
        assert result["preview"]["active"] is True
        assert result["preview"]["source_id"] == "S002"
        assert result["preview"]["proposed_offset_s"] == 3600.0
        assert result["preview"]["persistent_changes_made"] is False
        assert result["preview"]["events_from_source_with_recalculated_time"] > 0
        assert any(event["preview_utc"] for event in result["events"])
        assert all(
            (case_path / name).read_bytes() == content
            for name, content in (("case.json", before["case"]),
                                  ("normalised/events.jsonl", before["events"]),
                                  ("custody.jsonl", before["custody"]))
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_time_analysis_flags_and_exact_cross_source_timestamp_ties(tmp_path: Path) -> None:
    case_path = _case(tmp_path)
    event_path = case_path / "normalised" / "events.jsonl"
    records = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert records[0]["source_id"] != records[4]["source_id"]
    records[4]["ts_utc"] = records[0]["ts_utc"]
    records[0]["tz_assumed"] = True
    records[1]["year_inferred"] = True
    records[2].setdefault("extra", {})["dst_ambiguous"] = True
    event_path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

    server, thread, base = _serve(case_path)
    try:
        result = _get(base + "/api/time-analysis?limit=100")
        assert result["summary"]["timezone_assumed_events"] == 1
        assert result["summary"]["year_inferred_events"] == 1
        assert result["summary"]["dst_ambiguous_events"] == 1
        assert result["summary"]["events_flagged_for_time_review"] == 3
        assert result["timestamp_ties"]["total_groups"] >= 1
        flagged = _get(base + "/api/time-analysis?issues_only=1&limit=100")
        assert len(flagged["events"]) == 3
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_time_analysis_rejects_unknown_sources_and_bad_offsets(tmp_path: Path) -> None:
    case_path = _case(tmp_path)
    server, thread, base = _serve(case_path)
    try:
        for query in (
            urlencode({"preview_source_id": "S999", "preview_offset_s": "12"}),
            urlencode({"preview_source_id": "S001", "preview_offset_s": "nan"}),
            urlencode({"source_id": "S999"}),
        ):
            try:
                urlopen(base + "/api/time-analysis?" + query)
                assert False, f"expected HTTP 400 for query {query}"
            except HTTPError as exc:
                assert exc.code == 400
                assert "error" in json.loads(exc.read())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_timestamp_precision_reports_missing_components_honestly() -> None:
    from incident_timeline.time_analysis import _precision

    assert _precision("2026-10-23T10:20Z") == (60.0, "Minute-level timestamp; seconds omitted")
    assert _precision("2026-10-23T00:00:00Z") == (1.0, "Seconds recorded; no fractional part")
    precision, label = _precision("2026-10-23T00:00:00.123456789Z")
    assert precision == 1e-6
    assert "9 fractional digits recorded" in label
    assert "1 µs" in label
    assert _precision("2026-10-23")[0] == 86400.0
    assert _precision("unrecognized timestamp")[0] is None


def test_mixed_saved_offsets_are_flagged_for_review(tmp_path: Path) -> None:
    case_path = _case(tmp_path)
    event_path = case_path / "normalised" / "events.jsonl"
    records = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    source_id = records[0]["source_id"]
    source_records = [record for record in records if record["source_id"] == source_id]
    assert len(source_records) >= 2
    source_records[0]["skew_offset_s"] = 30.0
    source_records[1]["skew_offset_s"] = -45.0
    event_path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

    server, thread, base = _serve(case_path)
    try:
        result = _get(base + "/api/time-analysis?limit=100")
        source = next(item for item in result["sources"] if item["source_id"] == source_id)
        assert source["applied_offset_s"] is None
        assert source["offset_settings_match"] is False
        assert source["recorded_offset_values_s"] == [-45.0, 0.0, 30.0]
        assert result["summary"]["sources_where_settings_differ_from_parsed_timeline"] >= 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
