from datetime import datetime

from incident_timeline.parsers.syslog import infer_years, interpret, parse_syslog
from incident_timeline.timeutil import to_rfc3339


def stamps(*months):
    return [(m, 15, 12, 0, 0, 0) for m in months]


class TestInferYears:
    def test_rollover_with_reference(self):
        assert infer_years(stamps(12, 12, 1, 1), None, datetime(2027, 1, 20)) == [2026, 2026, 2027, 2027]

    def test_explicit_year_is_first_line(self):
        assert infer_years(stamps(11, 12, 1), 2026, None) == [2026, 2026, 2027]

    def test_log_newer_than_reference_goes_back_a_year(self):
        # Copied in March 2026 without keeping mtime; November lines must be 2025.
        assert infer_years(stamps(11, 11), None, datetime(2026, 3, 1)) == [2025, 2025]

    def test_small_backward_step_is_not_a_new_year(self):
        assert infer_years(stamps(3, 2, 3), 2026, None) == [2026, 2026, 2026]

    def test_two_rollovers(self):
        assert infer_years(stamps(12, 1, 12, 1), 2025, None) == [2025, 2026, 2026, 2027]


def test_auth_log_sample(make_ctx):
    ctx = make_ctx(sample="auth.log", tz="Asia/Kolkata",
                   reference=datetime.fromisoformat("2027-01-01T00:10:00+05:30"))
    r = parse_syslog(ctx)

    assert r.lines == 13 and r.blank_lines == 1
    assert len(r.events) == 11
    assert [(g.line_no, g.reason) for g in r.gaps] == [(12, "no syslog timestamp format matched")]

    by_line = {e.line_no: e for e in r.events}
    first = by_line[1]
    assert to_rfc3339(first.ts_utc) == "2026-12-31T18:28:01Z"
    assert first.ts_raw == "Dec 31 23:58:01"
    assert (first.host, first.process, first.pid) == ("web01", "sshd", 1201)
    assert (first.user, first.src_ip, first.action, first.outcome) == ("admin", "203.0.113.7", "ssh_login", "failure")
    assert first.extra["invalid_user"] is True and first.year_inferred and not first.tz_assumed

    assert to_rfc3339(by_line[4].ts_utc) == "2026-12-31T18:30:12Z"  # Jan 1 2027 IST
    assert (by_line[4].user, by_line[4].outcome, by_line[4].extra["method"]) == ("alice", "success", "password")
    assert by_line[5].action == "session_opened" and by_line[5].user == "alice"
    assert by_line[6].action == "sudo_command" and by_line[6].outcome == "success"
    assert by_line[6].extra["command"] == "/usr/bin/cat /etc/shadow"
    assert by_line[7].user == "root" and by_line[7].extra["by"] == "alice"
    assert by_line[8].outcome == "failure" and by_line[8].extra["problem"] == "3 incorrect password attempts"
    assert by_line[10].action == "user_created" and by_line[10].user == "backdoor"
    assert by_line[11].action == "cron_command" and by_line[11].user == "root"
    assert by_line[13].action == "ssh_disconnect" and by_line[13].src_ip == "203.0.113.7"
    assert all(e.raw_line for e in r.events)
    assert any("year inferred" in n for n in r.notes)


def test_explicit_year_overrides_inference(make_ctx):
    ctx = make_ctx(["Jan  5 10:00:00 h1 sshd[1]: Connection from 10.0.0.1 port 22"], year=2024)
    e = parse_syslog(ctx).events[0]
    assert e.ts_utc.year == 2024 and not e.year_inferred


def test_iso_and_rfc5424_sample(make_ctx):
    r = parse_syslog(make_ctx(sample="syslog_iso.log", tz="Asia/Kolkata"))
    by_line = {e.line_no: e for e in r.events}
    assert to_rfc3339(by_line[1].ts_utc) == "2026-12-31T18:30:13.204511Z"
    assert by_line[1].tz == "+05:30" and not by_line[1].year_inferred
    assert by_line[2].process == "kernel" and by_line[2].host == "db01"
    rfc = by_line[3]
    assert to_rfc3339(rfc.ts_utc) == "2026-12-31T18:32:00.500000Z"
    assert (rfc.host, rfc.process, rfc.pid, rfc.user, rfc.src_ip) == ("db01", "sshd", 2201, "backup", "10.0.0.9")
    assert rfc.extra["structured_data"] == '[origin ip="10.0.0.9"]'
    assert rfc.extra["severity"] == 6
    # No offset in the line: the source zone applies.
    assert to_rfc3339(by_line[5].ts_utc) == "2026-12-31T18:29:59Z" and by_line[5].tz == "Asia/Kolkata"
    assert [g.line_no for g in r.gaps] == [4]


def test_missing_zone_is_flagged(make_ctx):
    ctx = make_ctx(["Oct 12 13:37:01 web01 sshd[812]: Connection from 10.0.0.1 port 22"],
                   year=2026, tz="UTC", tz_assumed=True)
    e = parse_syslog(ctx).events[0]
    assert e.tz_assumed and to_rfc3339(e.ts_utc) == "2026-10-12T13:37:01Z"


def test_dst_ambiguous_is_flagged(make_ctx):
    ctx = make_ctx(["Nov  1 01:30:00 h1 cron[1]: tick"], year=2026, tz="America/New_York")
    assert parse_syslog(ctx).events[0].extra["dst_ambiguous"] is True


def test_feb_29_in_non_leap_year_becomes_gap(make_ctx):
    r = parse_syslog(make_ctx(["Feb 29 10:00:00 h1 app: x"], year=2026))
    assert not r.events and "invalid date" in r.gaps[0].reason


def test_crlf_and_invalid_utf8_are_kept(make_ctx, tmp_path):
    ctx = make_ctx([], year=2026)
    ctx.evidence_path.write_bytes(b"Oct 12 13:37:01 h1 app: caf\xe9\r\n\xff\xfe junk\r\n")
    r = parse_syslog(ctx)
    assert r.events[0].message == "caf\\xe9"
    assert r.gaps[0].raw_line == "\\xff\\xfe junk"


def test_unknown_message_is_still_an_event(make_ctx):
    e = parse_syslog(make_ctx(["Oct 12 13:37:01 h1 nginx[9]: worker started"], year=2026)).events[0]
    assert e.action is None and e.process == "nginx" and e.message == "worker started"


def test_interpret_newer_sshd_and_pam_auth_failure():
    info = interpret("sshd-session", "Failed publickey for git from 2001:db8::1 port 4022 ssh2")
    assert (info["user"], info["src_ip"]) == ("git", "2001:db8::1")
    info = interpret("sshd", "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
                             "tty=ssh ruser= rhost=198.51.100.4  user=root")
    assert (info["action"], info["user"], info["src_ip"]) == ("auth_failure", "root", "198.51.100.4")


def test_interpret_hostname_instead_of_ip():
    info = interpret("sshd", "Accepted password for bob from attacker.example port 22 ssh2")
    assert info["src_ip"] is None and info["extra"]["remote_host"] == "attacker.example"
