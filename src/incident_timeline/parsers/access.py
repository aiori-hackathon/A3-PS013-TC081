"""Apache / Nginx access-log parser (Common and Combined Log Format).

    203.0.113.7 - alice [12/Oct/2026:13:37:01 +0530] "GET /admin HTTP/1.1" 403 512 "-" "curl/8.5"

The timestamp carries its own offset, so the source's zone is only used
for custom formats that omit it. An optional leading "vhost:port" field
(Apache vhost_combined) and trailing extra fields are accepted.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

from ..models import Event, SourceContext
from ..timeutil import (
    MONTHS, frac_to_us, localize, offset_label, parse_offset, parse_rfc3339, resolve_tz, to_utc,
)
from . import ParseResult, read_lines

_Q = r'"(?P<{}>(?:[^"\\]|\\.)*)"'
LINE_RE = re.compile(
    r"^(?:(?P<vhost>\S+:\d+) )?"
    r"(?P<client>\S+) (?P<ident>\S+) (?P<authuser>.+?) \[(?P<ts>[^\]]+)\] "
    + _Q.format("request")
    + r" (?P<status>\d{3}|-) (?P<size>\d+|-)"
    + r"(?: " + _Q.format("referer") + " " + _Q.format("agent") + r")?"
    + r"(?P<trailing>.*)$"
)
CLF_TS_RE = re.compile(
    r"^(?P<day>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
    r"(?:\.(?P<frac>\d{1,9}))?(?: (?P<off>[+-]\d{4}))?$"
)
REQUEST_RE = re.compile(r"^(?P<method>[A-Z][A-Z0-9_-]*) (?P<target>\S+)(?: (?P<protocol>HTTP/\d(?:\.\d)?))?$")


def _dash(v: str | None) -> str | None:
    return None if v in (None, "-", "") else v


def _parse_ts(text: str, tz: Any, ctx: SourceContext) -> tuple[datetime, str, bool, bool]:
    """Return (aware ts, zone label, tz_assumed, dst_ambiguous)."""
    m = CLF_TS_RE.match(text)
    if m:
        mon = MONTHS.get(m["mon"].lower())
        if mon is None:
            raise ValueError(f"unknown month {m['mon']!r}")
        naive = datetime(int(m["year"]), mon, int(m["day"]), int(m["h"]), int(m["m"]),
                         int(m["s"]), frac_to_us(m["frac"]))
        if m["off"]:
            aware = naive.replace(tzinfo=parse_offset(m["off"]))
            return aware, offset_label(aware), False, False
        aware, ambiguous = localize(naive, tz)
        return aware, ctx.tz, ctx.tz_assumed, ambiguous
    ts = parse_rfc3339(text)  # e.g. nginx $time_iso8601
    if ts.tzinfo is None:
        aware, ambiguous = localize(ts, tz)
        return aware, ctx.tz, ctx.tz_assumed, ambiguous
    return ts, offset_label(ts), False, False


def parse_access(ctx: SourceContext) -> ParseResult:
    tz = resolve_tz(ctx.tz)
    result = ParseResult()
    for line_no, raw in read_lines(ctx.evidence_path):
        result.lines += 1
        if not raw.strip():
            result.blank_lines += 1
            continue
        m = LINE_RE.match(raw)
        if not m:
            result.gap(ctx, line_no, raw, "no access-log format matched")
            continue
        try:
            ts, zone, assumed, ambiguous = _parse_ts(m["ts"], tz, ctx)
        except ValueError as exc:
            result.gap(ctx, line_no, raw, f"bad access-log timestamp {m['ts']!r}: {exc}")
            continue

        extra: dict[str, Any] = {}
        request = m["request"]
        rm = REQUEST_RE.match(request)
        if rm:
            extra["method"] = rm["method"]
            extra["path"] = rm["target"]
            if rm["protocol"]:
                extra["protocol"] = rm["protocol"]
        elif request not in ("", "-"):
            extra["request_malformed"] = True

        status = None if m["status"] == "-" else int(m["status"])
        extra["status"] = status
        extra["bytes"] = None if m["size"] == "-" else int(m["size"])
        if _dash(m["referer"]):
            extra["referer"] = m["referer"]
        if _dash(m["agent"]):
            extra["user_agent"] = m["agent"]
        if m["vhost"]:
            extra["vhost"] = m["vhost"]
        if m["trailing"].strip():
            extra["trailing"] = m["trailing"].strip()
        if ambiguous:
            extra["dst_ambiguous"] = True

        client = m["client"]
        try:
            src_ip = str(ipaddress.ip_address(client))
        except ValueError:
            src_ip = None
            extra["client"] = client

        outcome = None
        if status is not None:
            outcome = "failure" if status >= 400 else "success"

        result.events.append(Event(
            ts_utc=to_utc(ts),
            ts_raw=m["ts"],
            source_id=ctx.source_id,
            source_type=ctx.source_type,
            source_file=ctx.source_file,
            file_sha256=ctx.file_sha256,
            line_no=line_no,
            raw_line=raw,
            host=ctx.host,
            user=_dash(m["authuser"]),
            src_ip=src_ip,
            action="http_request",
            outcome=outcome,
            message=request,
            tz=zone,
            tz_assumed=assumed,
            extra=extra,
        ))
    return result
