"""The Vercel entry point (api/index.py): restoring cases a serverless instance lost."""
from __future__ import annotations

import importlib.util
import io
import json
import tarfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from incident_timeline.evidence import Case

API = Path(__file__).resolve().parents[2] / "api" / "index.py"
SAMPLE = Path(__file__).resolve().parents[2] / "demo-evidence" / "web01" / "auth.log"


@pytest.fixture()
def hosted(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("orisect_vercel_index", API)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    root = (tmp_path / "cases").resolve()
    root.mkdir()
    monkeypatch.setattr(mod, "CASES_ROOT", root)
    handler = type("H", (mod.handler,), {"case_root": root, "cases_root": root})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield mod, root, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _upload(base: str) -> tuple[str, bytes, str, str]:
    boundary = "b0undary"
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="case_name"\r\n\r\nhosted\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="type_0"\r\n\r\nauth\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="file_0"; filename="auth.log"\r\n\r\n').encode() \
        + SAMPLE.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    req = Request(base + "/upload", data=body, method="POST", headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}", "X-Orisect-Archive": "1"})
    with urlopen(req) as r:
        assert r.headers["Content-Type"] == "application/gzip"
        return r.headers["X-Orisect-Case"], r.read(), r.headers["X-Orisect-Version"], r.headers["X-Orisect-Signature"]


def _restore(base, case_id, data, version, signature):
    req = Request(f"{base}/api/case-restore?case={case_id}", data=data, method="POST", headers={
        "Content-Type": "application/gzip", "X-Orisect-Version": version, "X-Orisect-Signature": signature})
    with urlopen(req) as r:
        return json.loads(r.read())


def test_lost_case_is_restored_from_the_signed_archive(hosted):
    mod, root, base = hosted
    case_id, data, version, signature = _upload(base)
    import shutil
    shutil.rmtree(root / case_id)
    with pytest.raises(HTTPError) as missing:
        urlopen(f"{base}/api/summary?case={case_id}")
    assert missing.value.code == 404
    assert _restore(base, case_id, data, version, signature)["restored"] is True
    with urlopen(f"{base}/api/summary?case={case_id}") as r:
        assert json.loads(r.read())["integrity_ok"] is True


def test_stale_instance_answers_409_and_accepts_the_newer_copy(hosted):
    mod, root, base = hosted
    case_id, old_data, old_version, old_sig = _upload(base)
    Case.open(root / case_id).append_custody("note", actor="test")
    with urlopen(f"{base}/api/case-archive?case={case_id}") as r:
        new_data, new_version, new_sig = r.read(), r.headers["X-Orisect-Version"], r.headers["X-Orisect-Signature"]
    import shutil
    shutil.rmtree(root / case_id)
    _restore(base, case_id, old_data, old_version, old_sig)  # this instance now holds the older copy
    req = Request(f"{base}/api/summary?case={case_id}", headers={"X-Orisect-Expect": new_version})
    with pytest.raises(HTTPError) as stale:
        urlopen(req)
    assert stale.value.code == 409 and json.loads(stale.value.read())["stale"] is True
    assert _restore(base, case_id, new_data, new_version, new_sig)["restored"] is True
    assert mod.case_version(root / case_id) == new_version
    # An older archive never replaces a newer copy.
    assert _restore(base, case_id, old_data, old_version, old_sig)["restored"] is False


def test_forged_or_unsafe_archives_are_refused(hosted):
    mod, root, base = hosted
    case_id, data, version, signature = _upload(base)
    with pytest.raises(HTTPError) as forged:
        _restore(base, "CASE-aaaaaaaaaaaa", data, version, signature)  # signature is bound to the case id
    assert forged.value.code == 403
    evil = io.BytesIO()
    with tarfile.open(fileobj=evil, mode="w:gz") as tar:
        info = tarfile.TarInfo("../escape.txt"); payload = b"x"; info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    with pytest.raises(ValueError):
        mod.extract_archive(evil.getvalue(), root / "x")
    with urlopen(f"{base}/api/cases") as r:
        assert json.loads(r.read()) == {"cases": []}
