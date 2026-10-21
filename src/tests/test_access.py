from incident_timeline.parsers.access import parse_access
from incident_timeline.timeutil import to_rfc3339


def test_access_log_sample(make_ctx):
    r = parse_access(make_ctx(sample="access.log", source_type="access", host="web01"))
    assert len(r.events) == 6
    assert [(g.line_no, g.reason) for g in r.gaps] == [(7, "no access-log format matched")]

    by_line = {e.line_no: e for e in r.events}
    e = by_line[1]
    assert to_rfc3339(e.ts_utc) == "2026-12-31T18:20:01Z"
    assert (e.src_ip, e.host, e.action, e.outcome, e.tz) == ("203.0.113.7", "web01", "http_request", "success", "+05:30")
    assert e.extra == {"method": "GET", "path": "/", "protocol": "HTTP/1.1", "status": 200, "bytes": 3120,
                       "user_agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    assert by_line[2].outcome == "failure" and by_line[2].extra["user_agent"] == "sqlmap/1.8"
    assert by_line[3].extra["referer"] == "http://web01/upload"
    assert by_line[4].extra["path"] == "/uploads/shell.php?cmd=id"
    # Common Log Format (no referer / agent), IPv6 client, authenticated user
    assert (by_line[5].src_ip, by_line[5].user, by_line[5].extra["status"]) == ("2001:db8::5", "bob", 401)
    assert by_line[6].extra["request_malformed"] is True
    assert not any(ev.tz_assumed for ev in r.events)


def test_vhost_prefix_and_trailing_fields(make_ctx):
    line = ('example.com:443 10.1.1.1 - - [12/Oct/2026:13:37:01 +0000] "GET /x HTTP/2.0" 200 5 "-" "ua" 0.003')
    e = parse_access(make_ctx([line], source_type="access")).events[0]
    assert e.extra["vhost"] == "example.com:443" and e.extra["trailing"] == "0.003"
    assert e.extra["protocol"] == "HTTP/2.0"


def test_hostname_client_and_dash_size(make_ctx):
    line = 'proxy.internal - - [12/Oct/2026:13:37:01 -0700] "HEAD / HTTP/1.0" 304 -'
    e = parse_access(make_ctx([line], source_type="access")).events[0]
    assert e.src_ip is None and e.extra["client"] == "proxy.internal"
    assert e.extra["bytes"] is None and to_rfc3339(e.ts_utc) == "2026-10-12T20:37:01Z"


def test_timestamp_without_offset_uses_source_zone(make_ctx):
    line = '10.0.0.1 - - [12/Oct/2026:13:37:01] "GET / HTTP/1.1" 200 1'
    e = parse_access(make_ctx([line], source_type="access", tz="Asia/Kolkata")).events[0]
    assert to_rfc3339(e.ts_utc) == "2026-10-12T08:07:01Z" and e.tz == "Asia/Kolkata"


def test_bad_date_becomes_gap(make_ctx):
    line = '10.0.0.1 - - [31/Feb/2026:13:37:01 +0000] "GET / HTTP/1.1" 200 1'
    r = parse_access(make_ctx([line], source_type="access"))
    assert not r.events and r.gaps[0].reason.startswith("bad access-log timestamp")
