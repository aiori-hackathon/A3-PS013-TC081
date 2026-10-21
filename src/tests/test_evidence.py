import hashlib
import json
import os
import stat

import pytest

from incident_timeline.evidence import Case, EvidenceError, collect, verify, verify_chain

from .conftest import DATA


def _make_writable(path):
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


@pytest.fixture
def case(tmp_path):
    return Case.open(tmp_path / "case", create=True)


def test_collect_copies_hashes_and_locks(case):
    s = collect(case, DATA / "auth.log", "auth", tz="Asia/Kolkata", note="from web01")
    original = (DATA / "auth.log").read_bytes()
    stored = case.root / s["evidence_path"]

    assert s["source_id"] == "S001" and s["source_type"] == "syslog"
    assert s["sha256"] == hashlib.sha256(original).hexdigest()
    assert stored.read_bytes() == original
    assert stat.S_IMODE(os.stat(stored).st_mode) & 0o222 == 0  # no write bits
    assert int(os.stat(stored).st_mtime) == int(os.stat(DATA / "auth.log").st_mtime)

    rec = case.read_custody()[0]
    assert rec["action"] == "collect" and rec["sha256"] == s["sha256"] and rec["note"] == "from web01"
    assert rec["prev_sha256"] == "0" * 64


def test_verify_passes_then_detects_tampered_evidence(case):
    s = collect(case, DATA / "auth.log", "auth")
    assert verify(case).ok

    stored = case.root / s["evidence_path"]
    _make_writable(stored)
    stored.write_bytes(stored.read_bytes().replace(b"alice", b"mallory"))

    report = verify(case)
    assert not report.ok and "hash mismatch" in report.files_bad[0]
    assert case.read_custody()[-1]["result"] == "fail"


def test_custody_chain_detects_edits_and_deletions(case):
    collect(case, DATA / "auth.log", "auth")
    collect(case, DATA / "access.log", "access")
    verify(case)
    assert verify_chain(case) == []

    lines = case.custody_file.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["actor"] = "someone-else"
    edited = [json.dumps(rec)] + lines[1:]
    case.custody_file.write_text("\n".join(edited) + "\n", encoding="utf-8")
    assert any("contents do not match" in e for e in verify_chain(case))

    case.custody_file.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    errors = verify_chain(case)
    assert any("link to previous record is broken" in e for e in errors)


def test_verify_uses_custody_hash_not_case_json(case):
    s = collect(case, DATA / "auth.log", "auth")
    stored = case.root / s["evidence_path"]
    _make_writable(stored)
    stored.write_bytes(b"replaced\n")
    # Someone "fixes" case.json to match the tampered file; custody still disagrees.
    case.update_source("S001", sha256=hashlib.sha256(b"replaced\n").hexdigest(), size=9)
    assert not verify(case).ok


def test_duplicate_content_is_refused(case, tmp_path):
    collect(case, DATA / "auth.log", "auth")
    copy = tmp_path / "auth-copy.log"
    copy.write_bytes((DATA / "auth.log").read_bytes())
    with pytest.raises(EvidenceError, match="already collected as S001"):
        collect(case, copy, "auth")
    assert not list(case.evidence_dir.glob("*.partial"))
    assert collect(case, copy, "auth", allow_duplicate=True)["source_id"] == "S002"


def test_bad_inputs(case, tmp_path):
    with pytest.raises(EvidenceError, match="not a file"):
        collect(case, tmp_path / "missing.log", "auth")
    with pytest.raises(EvidenceError, match="unknown source type"):
        collect(case, DATA / "auth.log", "windows-evtx")
    with pytest.raises(ValueError, match="unknown time zone"):
        collect(case, DATA / "auth.log", "auth", tz="Not/AZone")
    assert case.sources() == [] and case.read_custody() == []


def test_open_missing_case(tmp_path):
    with pytest.raises(EvidenceError, match="no case"):
        Case.open(tmp_path / "nope")
