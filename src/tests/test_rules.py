from __future__ import annotations

import json
from pathlib import Path

import pytest

from incident_timeline.evidence import Case, collect, verify_chain
from incident_timeline.findings import detect
from incident_timeline.pipeline import approve_rule, build_timeline, dry_run_rule, suggest_rule
from incident_timeline.rules import RuleError, active_rules, revoke, rule_hash, suggest, validate

FIREWALL = Path(__file__).resolve().parents[2] / "demo-evidence" / "fw01" / "fw01-traffic.log"

APP_LOG = """\
2026-10-25 08:41:12,331 INFO  [worker-3] login ok user=alice ip=10.0.8.15
2026-10-25 08:41:19,004 WARN  [worker-1] login failed user=bob ip=203.0.113.9
2026-10-25 08:42:01,550 INFO  [worker-3] export done user=alice ip=10.0.8.15
"""
LEGACY_LOG = """\
[25/10/2026 14:11:02] web01 BACKUP started 4122
[25/10/2026 14:11:39] web01 BACKUP finished 4122
[26/10/2026 02:00:00] web01 BACKUP started 4188
"""


def _case(tmp_path: Path, text: str | None = None, name: str = "app.log", tz: str | None = None) -> Case:
    source = tmp_path / name
    if text is None:
        source.write_bytes(FIREWALL.read_bytes())
    else:
        source.write_text(text, encoding="utf-8")
    case = Case.open(tmp_path / "case", create=True)
    collect(case, source, "other", tz=tz, host="h1")
    build_timeline(case)
    return case


def test_unknown_formats_are_kept_as_unparsed_lines(tmp_path: Path) -> None:
    case = _case(tmp_path, APP_LOG)
    summary = json.loads((case.output_dir / "summary.json").read_text())
    assert (summary["events"], summary["gaps"]) == (0, 3)
    gaps = [json.loads(line) for line in (case.output_dir / "gaps.jsonl").read_text().splitlines()]
    assert all("add a parser rule" in g["reason"] for g in gaps)


def test_firewall_key_value_rule_is_suggested_with_offsets_and_mappings() -> None:
    lines = FIREWALL.read_text().splitlines()
    proposal = suggest(lines, ["S001"])
    d = proposal["definition"]
    assert d["mode"] == "kv" and d["pattern"] is None
    assert d["timestamp"] == {"fields": ["date", "time", "tz"], "format": "%Y-%m-%d %H:%M:%S %z"}
    assert d["outcome"] == {"field": "action", "success": ["accept", "close"], "failure": ["deny"]}
    assert d["action"] == "network_connection"
    assert any("no time zone has to be assumed" in n for n in proposal["notes"])


def test_regex_rule_is_suggested_for_a_columnar_log(tmp_path: Path) -> None:
    case = _case(tmp_path, APP_LOG, tz="Asia/Kolkata")
    proposal = suggest_rule(case, "S001")
    d = proposal["definition"]
    assert d["mode"] == "regex" and d["timestamp"]["fields"] == ["ts"]
    assert proposal["test"]["lines_parsed"] == 3
    first = proposal["test"]["examples"][0]
    # 08:41:12 in Asia/Kolkata is 03:11:12 UTC; the comma decimal is kept.
    assert first["ts_utc"] == "2026-10-25T03:11:12.331000Z"
    assert first["tz_assumed"] is False


def test_day_first_dates_are_recognised(tmp_path: Path) -> None:
    case = _case(tmp_path, LEGACY_LOG)
    proposal = suggest_rule(case, "S001")
    assert proposal["definition"]["timestamp"]["format"] == "%d/%m/%Y %H:%M:%S"
    assert proposal["test"]["lines_parsed"] == 3
    assert proposal["test"]["examples"][2]["ts_utc"] == "2026-10-26T02:00:00Z"
    assert proposal["test"]["examples"][0]["tz_assumed"] is True  # no --tz given: flagged


def test_validation_rejects_unsafe_or_incomplete_rules() -> None:
    base = {"name": "x", "source_ids": ["S001"], "mode": "regex", "pattern": r"^(?P<ts>\S+) (?P<msg>.*)$",
            "timestamp": {"fields": ["ts"], "format": "iso8601"}, "action": "log_event",
            "outcome": None, "fields": {}, "message": "{msg}"}
    assert validate(base)["pattern"] == base["pattern"]
    for change, problem in (({"pattern": "(unclosed"}, "regular expression"),
                            ({"fields": {"user": "missing"}}, "no named group"),
                            ({"action": "Bad Action"}, "action"),
                            ({"source_ids": ["../etc"]}, "source_ids"),
                            ({"timestamp": {"fields": ["ts"], "format": "yyyy-mm-dd"}}, "strptime"),
                            ({"extra_key": 1}, "unknown rule keys")):
        with pytest.raises(RuleError, match=problem):
            validate({**base, **change})


def test_approved_rules_live_in_custody_and_survive_rebuilds(tmp_path: Path) -> None:
    case = _case(tmp_path)
    definition = suggest_rule(case, "S001")["definition"]
    record = approve_rule(case, definition, actor="tester")
    assert record["rule_sha256"] == rule_hash(validate(definition))
    out = build_timeline(case)
    assert (out.summary["events"], out.summary["gaps"]) == (71, 0)
    assert out.summary["sources"][0]["rule_events"] == {"R001": 71}
    assert case.read_custody()[-1]["parser_rules"] == {"R001": record["rule_sha256"]}
    assert not verify_chain(case)

    events = [e.to_dict() for e in out.events]
    assert all(e["extra"]["parser_rule"] == "R001" and e["tz"] == "+05:30" for e in events)
    exfil = [f for f in detect(events) if f["rule"] == "large_outbound_transfer"]
    assert len(exfil) == 1 and exfil[0]["entities"]["ips"] == ["10.0.2.11", "203.0.113.45"]

    revoke(case, "R001", actor="tester", reason="wrong format")
    assert active_rules(case) == []
    assert build_timeline(case).summary["events"] == 0
    with pytest.raises(RuleError):
        revoke(case, "R001")


def test_a_rule_edited_inside_the_custody_log_is_ignored(tmp_path: Path) -> None:
    case = _case(tmp_path)
    approve_rule(case, suggest_rule(case, "S001")["definition"])
    lines = case.custody_file.read_text().splitlines()
    record = json.loads(lines[-1])
    record["definition"]["action"] = "something_else"
    lines[-1] = json.dumps(record)
    case.custody_file.write_text("\n".join(lines) + "\n")
    assert active_rules(case) == []  # its hash no longer matches, so it is not applied
    assert verify_chain(case)  # and the chain reports the edit


def test_approval_needs_a_rule_that_parses_something(tmp_path: Path) -> None:
    case = _case(tmp_path, APP_LOG)
    rule = {"name": "never", "source_ids": ["S001"], "mode": "regex", "pattern": r"^NOPE (?P<ts>\S+)$",
            "timestamp": {"fields": ["ts"], "format": "iso8601"}, "action": "log_event", "outcome": None,
            "fields": {}, "message": None}
    assert dry_run_rule(case, rule)["lines_unmatched"] == 3
    with pytest.raises(RuleError, match="does not parse"):
        approve_rule(case, rule)
