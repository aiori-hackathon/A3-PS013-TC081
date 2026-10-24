from __future__ import annotations

from pathlib import Path

from incident_timeline.findings import detect, entities
from incident_timeline.models import load_events
from incident_timeline.scenarios import create_demo_cases


def _scenario_events(tmp_path: Path, scenario_id: str) -> list[dict]:
    create_demo_cases(tmp_path / "demos")
    path = tmp_path / "demos" / scenario_id / "case" / "normalised" / "events.jsonl"
    return [event.to_dict() for event in load_events(path)]


def _event(line_no: int, ts: str, action: str, outcome: str | None = None, source_id: str = "S001", **fields) -> dict:
    return {"event_id": f"{source_id}:{line_no}", "source_id": source_id, "source_file": "auth.log", "line_no": line_no,
            "ts_utc": ts, "action": action, "outcome": outcome, "extra": fields.pop("extra", {}), **fields}


def test_brute_force_scenario_finds_login_after_failures(tmp_path: Path) -> None:
    findings = {f["rule"]: f for f in detect(_scenario_events(tmp_path, "01-brute-force-to-sudo"))}
    assert set(findings) == {"brute_force", "login_after_failures", "sensitive_file_access"}
    assert findings["login_after_failures"]["severity"] == "high"
    assert findings["login_after_failures"]["event_ids"] == ["S001:1", "S001:2", "S001:3", "S001:4"]
    assert findings["brute_force"]["technique"] == "T1110"
    assert findings["sensitive_file_access"]["event_ids"] == ["S001:6"]


def test_web_scenario_links_web_requests_to_ssh_across_sources(tmp_path: Path) -> None:
    findings = {f["rule"]: f for f in detect(_scenario_events(tmp_path, "02-web-exploit-to-server-access"))}
    assert {"web_to_ssh", "web_shell", "web_probing", "sensitive_file_access", "privileged_commands"} <= set(findings)
    pivot = findings["web_to_ssh"]
    assert pivot["entities"]["ips"] == ["203.0.113.88"]
    assert {i.split(":")[0] for i in pivot["event_ids"]} == {"S001", "S002"}
    assert findings["web_shell"]["event_ids"] == ["S001:2", "S001:3"]  # the upload, then the shell call


def test_persistence_scenario_flags_admin_account_and_cron(tmp_path: Path) -> None:
    findings = {f["rule"]: f for f in detect(_scenario_events(tmp_path, "03-account-persistence"))}
    assert findings["account_created"]["severity"] == "high"
    assert findings["account_created"]["entities"]["users"] == ["backdoor"]
    assert findings["suspicious_cron"]["event_ids"] == ["S001:6"]


def test_findings_are_sorted_most_severe_first(tmp_path: Path) -> None:
    severities = [f["severity"] for f in detect(_scenario_events(tmp_path, "02-web-exploit-to-server-access"))]
    order = {"high": 0, "medium": 1, "info": 2}
    assert severities == sorted(severities, key=order.__getitem__)


def test_quiet_timeline_produces_no_findings() -> None:
    events = [
        _event(1, "2026-10-21T09:00:00Z", "ssh_login", "success", user="alice", src_ip="10.0.0.5"),
        _event(2, "2026-10-21T09:00:01Z", "session_opened", "success", user="alice"),
        _event(3, "2026-10-21T09:05:00Z", "cron_command", user="root", extra={"command": "/usr/bin/logrotate /etc/logrotate.conf"}),
    ]
    assert detect(events) == []


def test_two_failures_are_not_brute_force_but_still_precede_a_login() -> None:
    events = [
        _event(1, "2026-10-21T09:00:00Z", "ssh_login", "failure", user="bob", src_ip="192.0.2.1"),
        _event(2, "2026-10-21T09:00:05Z", "ssh_login", "failure", user="bob", src_ip="192.0.2.1"),
        _event(3, "2026-10-21T09:00:09Z", "ssh_login", "success", user="bob", src_ip="192.0.2.1"),
    ]
    assert [f["rule"] for f in detect(events)] == ["login_after_failures"]


def test_assumed_time_zones_are_reported() -> None:
    events = [_event(1, "2026-10-21T09:00:00Z", "session_opened", "success", tz_assumed=True)]
    (finding,) = detect(events)
    assert finding["rule"] == "time_basis" and finding["severity"] == "info"


def test_entities_rank_addresses_seen_in_several_sources_first(tmp_path: Path) -> None:
    ips = entities(_scenario_events(tmp_path, "02-web-exploit-to-server-access"))["ips"]
    assert ips[0]["value"] == "203.0.113.88"
    assert ips[0]["sources"] == ["S001", "S002"]
    assert ips[0]["failures"] == 2
