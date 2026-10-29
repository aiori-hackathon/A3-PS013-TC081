from __future__ import annotations

import json
import re
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from incident_timeline.cli import main as cli_main
from incident_timeline.scenarios import create_demo_cases
from incident_timeline.web import TracefuseHandler, case_server_attrs


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
            assert b"ORISECT" in response.read()
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


SAMPLE_EVIDENCE = Path(__file__).resolve().parents[2] / "demo-evidence"


def _post_json(url: str, body: dict, headers: dict | None = None, expect: int = 200) -> dict:
    request = Request(url, data=json.dumps(body).encode(), method="POST",
                      headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urlopen(request) as response:
            assert response.status == expect
            return json.loads(response.read())
    except HTTPError as exc:
        assert exc.code == expect, exc.read()
        return json.loads(exc.read())


def _multipart(fields: dict[str, str], files: dict[str, Path]) -> tuple[bytes, str]:
    boundary = "----orisect-test-boundary"
    parts = []
    for name, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    for name, path in files.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{path.name}"\r\n'
                     f"Content-Type: application/octet-stream\r\n\r\n".encode() + path.read_bytes() + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def test_sample_evidence_walkthrough_through_the_web_app(tmp_path: Path) -> None:
    """The demo-evidence/ walkthrough, end to end: upload, investigate, export."""
    root = tmp_path.resolve()
    server, thread, base = _serve({"case_root": root, "cases_root": root, "app_mode": True})
    try:
        # The app no longer ships built-in demo investigations.
        for path in ("/demo", "/case/CASE-" + "0" * 12):
            try:
                urlopen(base + path)
                assert False, f"expected 404 for {path}"
            except HTTPError as exc:
                assert exc.code == 404

        files = {"file_0": SAMPLE_EVIDENCE / "edge01" / "access.log.1.gz",
                 "file_1": SAMPLE_EVIDENCE / "edge01" / "access.log",
                 "file_2": SAMPLE_EVIDENCE / "fw01" / "fw01-traffic.log",
                 "file_3": SAMPLE_EVIDENCE / "web01" / "auth.log"}
        fields = {"case_name": "web01 intrusion",
                  "type_0": "nginx", "tz_0": "UTC", "host_0": "edge01",
                  "type_1": "nginx", "tz_1": "UTC", "host_1": "edge01",
                  "type_2": "other", "tz_2": "UTC", "host_2": "fw01",
                  "type_3": "auth", "tz_3": "Asia/Kolkata", "host_3": ""}
        body, content_type = _multipart(fields, files)
        request = Request(base + "/upload", data=body, headers={"Content-Type": content_type}, method="POST")
        with urlopen(request) as response:  # follows the 303 to the new investigation
            assert response.status == 200
            case_id = re.search(r"/case/(CASE-[a-f0-9]{12})$", response.url).group(1)
            assert 'id="findings"' in response.read().decode("utf-8")

        q = "?case=" + case_id
        summary = _get(base + "/api/summary" + q)
        assert summary["case_name"] == "web01 intrusion"
        assert (summary["events"], summary["source_count"], summary["gaps"]) == (255, 4, 73)
        assert summary["integrity_ok"] is True
        fw = next(s for s in summary["sources"] if s["original_name"] == "fw01-traffic.log")
        assert (fw["source_type"], fw["events"], fw["gaps"]) == ("custom", 0, 71)
        rules = {f["rule"] for f in _get(base + "/api/insights" + q)["findings"]}
        assert len(_get(base + "/api/insights" + q)["findings"]) == 11
        assert {"web_shell", "login_after_failures", "brute_force", "web_probing", "sensitive_file_access",
                "account_created", "suspicious_cron", "time_basis", "privileged_commands"} <= rules
        # edge01's clock runs 187 s fast, so before correction the pivot is hidden.
        assert "web_to_ssh" not in rules
        access = next(s["source_id"] for s in summary["sources"] if s["original_name"] == "access.log")
        preview = _get(base + "/api/time-analysis" + q + f"&preview_source_id={access}&preview_offset_s=187")
        assert preview["preview"]["records_shifted_in_merged_order"] > 0
        # Teach ORISECT the firewall's format: suggest, test, approve, rebuild.
        proposal = _get(base + "/api/rules/suggest" + q + "&source_id=" + fw["source_id"])
        definition = proposal["definition"]
        assert definition["mode"] == "kv"
        assert definition["timestamp"] == {"fields": ["date", "time", "tz"], "format": "%Y-%m-%d %H:%M:%S %z"}
        assert {"src_ip": "srcip", "dst_ip": "dstip", "bytes_out": "sentbyte"}.items() <= definition["fields"].items()
        assert proposal["test"]["lines_parsed"] == 71
        test = _post_json(base + "/api/rules/test" + q, {"definition": definition})
        assert test["test"]["lines_parsed"] == 71 and test["test"]["examples"][0]["tz_assumed"] is False
        assert _post_json(base + "/api/rules/approve" + q, {"definition": definition}, expect=400)
        assert _post_json(base + "/api/rules/approve" + q, {"definition": definition, "analyst": "Analyst"},
                          headers={"Origin": "http://evil.example"}, expect=403)
        approved = _post_json(base + "/api/rules/approve" + q, {"definition": definition, "analyst": "Analyst"})
        assert approved["record"]["rule_id"] == "R001"
        assert (approved["events"], approved["gaps"]) == (326, 2)
        findings = _get(base + "/api/insights" + q)["findings"]
        exfil = next(f for f in findings if f["rule"] == "large_outbound_transfer")
        assert exfil["title"] == "Large upload from 10.0.2.11 to 203.0.113.45"
        assert len(exfil["event_ids"]) == 3 and "48.2 MB" in exfil["summary"]
        custody = _get(base + "/api/custody" + q)
        assert custody["chain_ok"] and [r["action"] for r in custody["records"]][-2:] == ["approve_parser_rule", "parse"]
        assert _get(base + "/api/rules" + q)["rules"][0]["approved_by"] == "Analyst (ORISECT web)"

        with urlopen(base + "/export/events.json" + q + "&ids=" + ",".join(exfil["event_ids"])) as response:
            scoped = json.loads(response.read())
        assert [e["event_id"] for e in scoped["events"]] == exfil["event_ids"]
        assert any(f["rule"] == "large_outbound_transfer" and len(f["evidence"]) == 3 for f in scoped["findings"])
        with urlopen(base + "/export/report.pdf" + q) as response:
            assert response.read(5) == b"%PDF-"

        revoked = _post_json(base + "/api/rules/revoke" + q, {"rule_id": "R001", "analyst": "Analyst", "reason": "test"})
        assert (revoked["events"], revoked["gaps"]) == (255, 73)
        assert _get(base + "/api/rules" + q)["rules"][0]["active"] is False

        with urlopen(base + "/tracefuse.css") as response:
            assert response.headers.get_content_type() == "text/css"
            assert b"--tf-accent" in response.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_sample_evidence_walkthrough_with_the_cli(tmp_path: Path) -> None:
    """The CLI half of the walkthrough: collect, verify, parse, estimate and apply skew."""
    case = tmp_path / "case"
    for args in (["collect", str(case), str(SAMPLE_EVIDENCE / "edge01" / "access.log.1.gz"), "--type", "nginx", "--host", "edge01"],
                 ["collect", str(case), str(SAMPLE_EVIDENCE / "edge01" / "access.log"), "--type", "nginx", "--host", "edge01"],
                 ["collect", str(case), str(SAMPLE_EVIDENCE / "web01" / "auth.log"), "--type", "auth", "--tz", "Asia/Kolkata", "--year", "2026"],
                 ["collect", str(case), str(SAMPLE_EVIDENCE / "fw01" / "fw01-traffic.log"), "--type", "other", "--host", "fw01"],
                 ["verify", str(case)], ["parse", str(case)],
                 ["rules", "suggest", str(case), "--source", "S004", "--out", str(tmp_path / "fw01-rule.json")],
                 ["rules", "approve", str(case), str(tmp_path / "fw01-rule.json")], ["parse", str(case)],
                 ["skew", str(case), "--reference", "S003", "--apply"], ["parse", str(case)]):
        assert cli_main(args) == 0, args
    meta = json.loads((case / "case.json").read_text())
    offsets = {s["source_id"]: s.get("skew_offset_s") for s in meta["sources"]}
    assert offsets["S001"] == offsets["S002"] == 187.0
    assert offsets["S004"] == 0.0  # the firewall's clock agrees with web01's
    events = [json.loads(line) for line in (case / "normalised" / "events.jsonl").read_text().splitlines()]
    read_config = next(e for e in events if "config.php" in (e.get("message") or ""))
    login = next(e for e in events if e["action"] == "ssh_login" and e["outcome"] == "success" and e["user"] == "deploy")
    assert read_config["ts_utc"] < login["ts_utc"]  # cause before effect once corrected
    from incident_timeline.findings import detect
    found = {f["rule"] for f in detect(events)}
    assert {"web_to_ssh", "large_outbound_transfer"} <= found
    assert len(events) == 326


def test_serve_accepts_a_folder_of_cases(tmp_path: Path) -> None:
    create_demo_cases(tmp_path / "demos")
    attrs, label = case_server_attrs(tmp_path / "demos")
    assert sorted(attrs["case_roots"]) == ["01-brute-force-to-sudo", "02-web-exploit-to-server-access", "03-account-persistence"]
    assert "3 cases" in label

    single, _ = case_server_attrs(tmp_path / "demos" / "01-brute-force-to-sudo" / "case")
    assert "case_roots" not in single

    server, thread, base = _serve(attrs)
    try:
        assert len(_get(base + "/api/cases")["cases"]) == 3
        for name in attrs["case_roots"]:
            assert _get(base + "/api/summary?case=" + name)["case_id"] == name
            assert _get(base + "/api/events?case=" + name)["total"] > 0
        with urlopen(base + "/fonts/inter-latin-var.woff2") as response:
            assert response.headers.get_content_type() == "font/woff2"
            assert "immutable" in response.headers["Cache-Control"]
        with urlopen(base + "/favicon.svg") as response:
            assert response.headers.get_content_type() == "image/svg+xml"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_rule_approval_is_refused_on_a_read_only_dashboard(tmp_path: Path) -> None:
    case = tmp_path / "case"
    assert cli_main(["collect", str(case), str(SAMPLE_EVIDENCE / "fw01" / "fw01-traffic.log"), "--type", "other"]) == 0
    assert cli_main(["parse", str(case)]) == 0
    server, thread, base = _serve({"case_root": case.resolve()})
    try:
        proposal = _get(base + "/api/rules/suggest?source_id=S001")
        assert _get(base + "/api/rules")["can_edit"] is False
        assert _post_json(base + "/api/rules/test", {"definition": proposal["definition"]})["test"]["lines_parsed"] == 71
        refused = _post_json(base + "/api/rules/approve", {"definition": proposal["definition"], "analyst": "A"}, expect=403)
        assert "read-only" in refused["error"]
        request = Request(base + "/api/rules/test", data=b"definition=x", method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            urlopen(request)
            assert False, "form posts must be refused"
        except HTTPError as exc:
            assert exc.code == 400
        bad = dict(proposal["definition"], pattern="(unclosed")
        assert "regular expression" in _post_json(base + "/api/rules/test", {"definition": bad}, expect=400)["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
