"""End-to-end: collect -> verify -> skew -> parse through the CLI."""

import json
import os
import shutil
import stat
from datetime import datetime

import pytest

from incident_timeline.cli import main
from incident_timeline.models import load_events

from .conftest import DATA


@pytest.fixture
def logs(tmp_path):
    """Sample logs with a fixed mtime so year inference is reproducible."""
    d = tmp_path / "logs"
    d.mkdir()
    mtime = datetime.fromisoformat("2027-01-01T00:10:00+05:30").timestamp()
    for name in ("auth.log", "access.log", "syslog_iso.log"):
        shutil.copyfile(DATA / name, d / name)
        os.utime(d / name, (mtime, mtime))
    return d


def run(*argv):
    return main([str(a) for a in argv])


def test_full_pipeline(tmp_path, logs, capsys):
    case = tmp_path / "case"
    assert run("collect", case, logs / "auth.log", "--type", "auth", "--tz", "Asia/Kolkata", "--actor", "ishaan") == 0
    assert run("collect", case, logs / "access.log", "--type", "nginx", "--host", "web01") == 0
    assert run("collect", case, logs / "syslog_iso.log", "--type", "syslog", "--tz", "+05:30") == 0
    assert run("sources", case) == 0
    assert run("verify", case) == 0
    assert run("parse", case) == 0
    out = capsys.readouterr().out
    assert "verification passed" in out and "21 events, 3 unparsed lines" in out

    events = list(load_events(case / "normalised" / "events.jsonl"))
    assert len(events) == 21
    assert [e.ts_utc for e in events] == sorted(e.ts_utc for e in events)
    shas = {json.loads(line)["sha256"] for line in (case / "custody.jsonl").read_text().splitlines()
            if '"collect"' in line}
    assert {e.file_sha256 for e in events} == shas
    assert events[0].event_id == "S002:1"

    gaps = [json.loads(line) for line in (case / "normalised" / "gaps.jsonl").read_text().splitlines()]
    assert [(g["source_id"], g["line_no"]) for g in gaps] == [("S001", 12), ("S002", 7), ("S003", 4)]

    summary = json.loads((case / "normalised" / "summary.json").read_text())
    s1 = summary["sources"][0]
    assert s1["events"] == 11 and s1["gaps"] == 1 and s1["year_inferred_events"] == 11
    assert s1["first_ts_utc"] == "2026-12-31T18:28:01Z"

    custody = [json.loads(line) for line in (case / "custody.jsonl").read_text().splitlines()]
    assert [r["action"] for r in custody] == ["collect", "collect", "collect", "verify", "parse"]
    assert custody[0]["actor"] == "ishaan"
    assert set(custody[-1]["outputs"]) == {"normalised/events.jsonl", "normalised/gaps.jsonl", "normalised/summary.json"}


def test_skew_set_anchor_and_estimate(tmp_path, logs, capsys):
    case = tmp_path / "case"
    run("collect", case, logs / "auth.log", "--type", "auth", "--tz", "Asia/Kolkata")
    run("collect", case, logs / "syslog_iso.log", "--type", "syslog", "--tz", "+05:30")

    # syslog_iso.log line 1 (S002) records the same login as auth.log line 4, 1.2 s later.
    assert run("skew", case, "--anchor", "S002:1=S001:4", "--apply") == 0
    out = capsys.readouterr().out
    assert "clock +1.205s (ahead)" in out and "applied to S002" in out

    run("parse", case)
    events = {e.event_id: e for e in load_events(case / "normalised" / "events.jsonl")}
    assert events["S002:1"].ts_utc == events["S001:4"].ts_utc
    assert events["S002:1"].skew_offset_s == pytest.approx(1.204511)

    assert run("skew", case, "--set", "S002=-30") == 0
    assert run("skew", case, "--reference", "S001") == 0
    assert "dry run" in capsys.readouterr().out
    actions = [json.loads(line)["action"] for line in (case / "custody.jsonl").read_text().splitlines()]
    assert actions.count("set_skew") == 2


def test_parse_refuses_tampered_evidence(tmp_path, logs, capsys):
    case = tmp_path / "case"
    run("collect", case, logs / "auth.log", "--type", "auth")
    stored = next((case / "evidence").iterdir())
    os.chmod(stored, stat.S_IRUSR | stat.S_IWUSR)
    stored.write_text("tampered\n")

    assert run("verify", case) == 1
    assert run("parse", case) == 2
    assert "refusing to parse" in capsys.readouterr().err
    assert run("parse", case, "--force") == 0


def test_errors_are_reported_not_raised(tmp_path, capsys):
    assert run("verify", tmp_path / "missing") == 2
    assert "no case" in capsys.readouterr().err
