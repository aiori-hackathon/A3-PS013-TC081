from __future__ import annotations

import json
import re
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import urlopen

from incident_timeline.scenarios import create_demo_cases
from incident_timeline.web import TracefuseHandler


def test_dashboard_api_filtering_evidence_and_exports(tmp_path: Path) -> None:
    create_demo_cases(tmp_path / "demos")
    case_path = tmp_path / "demos" / "01-brute-force-to-sudo" / "case"
    handler = type("TestTracefuseHandler", (TracefuseHandler,), {"case_root": case_path.resolve()})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urlopen(base + "/api/summary") as response:
            summary = json.loads(response.read())
        assert summary["case_id"] == "01-brute-force-to-sudo"
        assert summary["events"] == 6
        assert summary["integrity_ok"] is True

        query = urlencode({"action": "sudo_command", "limit": 10})
        with urlopen(base + "/api/events?" + query) as response:
            data = json.loads(response.read())
        assert data["total"] == 1
        assert data["events"][0]["action"] == "sudo_command"

        query = urlencode({"source_id": "S001", "line_no": 6})
        with urlopen(base + "/api/evidence?" + query) as response:
            evidence = json.loads(response.read())
        assert evidence["integrity_verified"] is True
        assert "/etc/shadow" in evidence["raw_line"]
        assert len(evidence["file_sha256"]) == 64

        with urlopen(base + "/export/events.json") as response:
            export = json.loads(response.read())
            assert response.headers.get_content_type() == "application/json"
        assert len(export["events"]) == 6

        with urlopen(base + "/export/report.pdf") as response:
            pdf = response.read()
            assert response.headers.get_content_type() == "application/pdf"
        assert pdf.startswith(b"%PDF-")

        with urlopen(base + "/") as response:
            assert b"TRACEFUSE" in response.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_evidence_endpoint_rejects_missing_line(tmp_path: Path) -> None:
    create_demo_cases(tmp_path / "demos")
    case_path = tmp_path / "demos" / "01-brute-force-to-sudo" / "case"
    handler = type("TestTracefuseHandler", (TracefuseHandler,), {"case_root": case_path.resolve()})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        query = urlencode({"source_id": "S001", "line_no": 999})
        try:
            urlopen(f"http://127.0.0.1:{server.server_address[1]}/api/evidence?{query}")
            assert False, "expected HTTP 400 for missing evidence line"
        except HTTPError as exc:
            assert exc.code == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_evidence_endpoint_refuses_tampered_source(tmp_path: Path) -> None:
    create_demo_cases(tmp_path / "demos")
    case_path = tmp_path / "demos" / "01-brute-force-to-sudo" / "case"
    metadata = json.loads((case_path / "case.json").read_text(encoding="utf-8"))
    evidence_path = case_path / metadata["sources"][0]["evidence_path"]
    evidence_path.chmod(0o600)
    evidence_path.write_text(evidence_path.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")

    handler = type("TestTracefuseHandler", (TracefuseHandler,), {"case_root": case_path.resolve()})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urlopen(base + "/api/summary") as response:
            summary = json.loads(response.read())
        assert summary["integrity_ok"] is False
        query = urlencode({"source_id": "S001", "line_no": 1})
        try:
            urlopen(base + "/api/evidence?" + query)
            assert False, "expected evidence integrity failure"
        except HTTPError as exc:
            assert exc.code == 409
            assert "integrity" in json.loads(exc.read())["error"].lower()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_evidence_endpoint_returns_the_line_the_event_cites(tmp_path: Path) -> None:
    """Gzipped logs and lines containing a lone carriage return must not shift line numbers."""
    import gzip

    from incident_timeline.evidence import Case, collect
    from incident_timeline.pipeline import build_timeline

    gz_log = tmp_path / "auth.log.gz"
    gz_log.write_bytes(gzip.compress(
        b"Oct 21 09:00:01 web01 sshd[1]: Accepted password for alice from 10.0.0.1 port 22 ssh2\n"))
    cr_log = tmp_path / "app.log"
    cr_log.write_bytes(b"Oct 21 09:00:01 web01 app[1]: weird\rpayload\n"
                       b"Oct 21 09:00:02 web01 sshd[1]: Accepted password for bob from 10.0.0.2 port 22 ssh2\n")
    case = Case.open(tmp_path / "case", create=True)
    collect(case, gz_log, "auth", year=2026)
    collect(case, cr_log, "auth", year=2026)
    events = build_timeline(case).events

    handler = type("TestTracefuseHandler", (TracefuseHandler,), {"case_root": case.root.resolve()})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        for event in events:
            query = urlencode({"source_id": event.source_id, "line_no": event.line_no})
            with urlopen(base + "/api/evidence?" + query) as response:
                evidence = json.loads(response.read())
            assert evidence["raw_line"] == event.raw_line
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _serve(attrs: dict):
    handler = type("TestTracefuseHandler", (TracefuseHandler,), attrs)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


def _get(url: str) -> dict:
    with urlopen(url) as response:
        return json.loads(response.read())


def test_insights_custody_and_gaps_endpoints(tmp_path: Path) -> None:
    create_demo_cases(tmp_path / "demos")
    case_path = tmp_path / "demos" / "02-web-exploit-to-server-access" / "case"
    server, thread, base = _serve({"case_root": case_path.resolve()})
    try:
        insights = _get(base + "/api/insights")
        rules = {f["rule"] for f in insights["findings"]}
        assert "web_to_ssh" in rules
        assert insights["entities"]["ips"][0]["value"] == "203.0.113.88"
        assert len(insights["activity"]["points"]) == 8 and insights["activity"]["sampled"] is False

        custody = _get(base + "/api/custody")
        assert custody["chain_ok"] is True
        assert [r["action"] for r in custody["records"]] == ["collect", "collect", "parse"]
        assert all("original_path" not in r["fields"] for r in custody["records"])

        gaps = _get(base + "/api/gaps")
        assert gaps == {"gaps": [], "total": 0, "offset": 0, "limit": 100}

        # The evidence behind one finding can be listed (and exported) on its own.
        pivot = next(f for f in insights["findings"] if f["rule"] == "web_to_ssh")
        events = _get(base + "/api/events?" + urlencode({"ids": ",".join(pivot["event_ids"])}))
        assert [e["event_id"] for e in events["events"]] == pivot["event_ids"]
        with urlopen(base + "/export/events.json?" + urlencode({"ids": pivot["event_ids"][0]})) as response:
            export = json.loads(response.read())
        assert len(export["events"]) == 1 and export["findings"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_custody_endpoint_marks_an_edited_record(tmp_path: Path) -> None:
    create_demo_cases(tmp_path / "demos")
    case_path = tmp_path / "demos" / "01-brute-force-to-sudo" / "case"
    custody_file = case_path / "custody.jsonl"
    lines = custody_file.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["note"] = "edited after the fact"
    custody_file.write_text("\n".join([json.dumps(first)] + lines[1:]) + "\n", encoding="utf-8")
    server, thread, base = _serve({"case_root": case_path.resolve()})
    try:
        custody = _get(base + "/api/custody")
        assert custody["chain_ok"] is False
        assert custody["records"][0]["ok"] is False
        assert "contents do not match" in custody["records"][0]["errors"][0]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_serving_a_folder_of_cases_switches_with_the_case_parameter(tmp_path: Path) -> None:
    from incident_timeline.web import discover_cases

    create_demo_cases(tmp_path / "demos")
    roots = discover_cases(tmp_path / "demos")
    assert list(roots) == ["01-brute-force-to-sudo", "02-web-exploit-to-server-access", "03-account-persistence"]
    server, thread, base = _serve({"case_root": next(iter(roots.values())), "case_roots": roots})
    try:
        cases = _get(base + "/api/cases")
        assert [c["id"] for c in cases["cases"]] == list(roots)
        assert _get(base + "/api/summary")["case_id"] == "01-brute-force-to-sudo"
        assert _get(base + "/api/summary?case=03-account-persistence")["case_id"] == "03-account-persistence"
        try:
            urlopen(base + "/api/summary?case=nope")
            assert False, "expected HTTP 400 for an unknown case"
        except HTTPError as exc:
            assert exc.code == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_engine_validation_page_and_scenario_catalog(tmp_path: Path) -> None:
    create_demo_cases(tmp_path / "demos")
    case_path = tmp_path / "demos" / "01-brute-force-to-sudo" / "case"
    server, thread, base = _serve({"case_root": case_path.resolve()})
    try:
        with urlopen(base + "/engine-test") as response:
            page = response.read().decode("utf-8")
            assert response.headers.get_content_type() == "text/html"
        assert "Engine Validation Lab" in page
        assert "Run full suite" in page
        assert "Run selected case" in page
        assert "Recent runs" in page

        catalogue = _get(base + "/api/benchmark/scenarios")
        assert catalogue["synthetic_data"] is True
        assert len(catalogue["scenarios"]) == 3
        assert catalogue["scenarios"][0]["input_files"] == ["auth.log"]
        assert catalogue["scenarios"][1]["expected_event_count"] == 8
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_benchmark_endpoint_supports_full_suite_and_single_scenario(tmp_path: Path) -> None:
    create_demo_cases(tmp_path / "demos")
    case_path = tmp_path / "demos" / "01-brute-force-to-sudo" / "case"
    server, thread, base = _serve({"case_root": case_path.resolve()})
    try:
        full = _get(base + "/api/benchmark")
        assert full["scope"] == "full-suite"
        assert len(full["scenarios"]) == 3
        assert all(result["synthetic_data"] is True for result in full["scenarios"])
        assert all(result["integrity_ok"] is True for result in full["scenarios"])
        assert all(result["passed"] is True for result in full["scenarios"])
        for result in full["scenarios"]:
            assert result["tracefuse_pipeline_ms"] >= 0
            assert result["checks"]["expected_timeline"]["passed"] is True
            assert result["checks"]["evidence_integrity"]["passed"] is True
            assert "case_path" not in result and "inputs_path" not in result

        one = _get(base + "/api/benchmark?scenario=03-account-persistence")
        assert one["scope"] == "single-scenario"
        assert len(one["scenarios"]) == 1
        assert one["scenarios"][0]["scenario_id"] == "03-account-persistence"
        assert one["scenarios"][0]["input_files"] == ["auth.log"]

        try:
            urlopen(base + "/api/benchmark?scenario=invalid-scenario")
            assert False, "expected HTTP 400 for unknown scenario"
        except HTTPError as exc:
            assert exc.code == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_app_mode_opens_demo_investigations_and_shared_styles(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    server, thread, base = _serve({"case_root": root, "cases_root": root, "app_mode": True})
    try:
        with urlopen(base + "/demo") as response:
            picker = response.read().decode("utf-8")
        case_links = re.findall(r'href="(/case/CASE-[a-f0-9]{12})"', picker)
        assert len(case_links) == 3
        for link in case_links:
            with urlopen(base + link) as response:
                page = response.read().decode("utf-8")
            assert response.status == 200
            assert 'id="findings"' in page
            assert "window.TRACEFUSE_CASE_ID" in page
        case_id = case_links[0].rsplit("/", 1)[1]
        summary = _get(base + "/api/summary?case=" + case_id)
        assert summary["case_id"] == "01-brute-force-to-sudo"
        assert "case_name" in summary

        with urlopen(base + "/tracefuse.css") as response:
            assert response.headers.get_content_type() == "text/css"
            assert b"--tf-accent" in response.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
