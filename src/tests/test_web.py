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
