"""Linux auth.log / syslog parser.

Handles three timestamp styles:
  * classic BSD syslog (RFC 3164): "Oct 12 13:37:01 web01 sshd[812]: ..."
    No year and no zone: the zone comes from the source settings and the
    year is inferred (see infer_years).
  * ISO / rsyslog high-precision: "2026-10-12T13:37:01.123456+05:30 web01 ..."
  * structured syslog (RFC 5424): "<34>1 2026-10-12T08:07:01Z web01 sshd 812 - - ..."

Known sshd, PAM, sudo, su, cron and account-management messages are
interpreted into user / src_ip / action / outcome. Other well-formed lines
are still events, just without an action.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta
from typing import Any

from ..models import Event, SourceContext
from ..timeutil import MONTHS, frac_to_us, localize, offset_label, parse_rfc3339, resolve_tz, to_utc
from . import ParseResult, read_lines

CLASSIC_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d{1,9}))?)"
    r"\s+(?P<rest>.*)$"
)
ISO_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?P<off>Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<rest>.*)$"
)
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) ?(?P<rest>.*)$"
)
TAG_RE = re.compile(r"^(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")
HOST_RE = re.compile(r"^[^\s\[:]+$")

# Month must drop by more than this many months to count as a new year.
ROLLOVER_MONTHS = 6


def infer_years(
    stamps: list[tuple[int, int, int, int, int, int]],
    explicit_year: int | None,
    reference: datetime | None,
) -> list[int]:
    """Assign a year to each (month, day, h, m, s, us) stamp, in file order.

    The year goes up by one whenever the month drops sharply (Dec -> Jan).
    With an explicit year, that is the first line's year. Otherwise the
    first year is chosen so the last line falls no later than the reference
    time (normally the file's modification time at collection) plus one day.
    reference must be naive local time in the source's zone.
    """
    if not stamps:
        return []
    rel = []
    bump = 0
    prev_month = stamps[0][0]
    for st in stamps:
        if prev_month - st[0] > ROLLOVER_MONTHS:
            bump += 1
        prev_month = st[0]
        rel.append(bump)

    if explicit_year is not None:
        base = explicit_year
    else:
        ref = reference or datetime.now()
        base = ref.year - bump
        mon, day, h, m, s, us = stamps[-1]
        last = datetime(base + bump, mon, min(day, 28), h, m, s, us)
        if mon == 2 and day == 29:
            last += timedelta(days=1)
        if last > ref + timedelta(days=1):
            base -= 1
    return [base + r for r in rel]


def _ip(text: str | None) -> str | None:
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text.strip("[]")))
    except ValueError:
        return None


# (regex, action, outcome). Named groups user/ip/port/method/... are lifted
# into the event; anything else lands in extra.
SSHD_RULES = [
    (r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)", "ssh_login", "failure"),
    (r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)", "ssh_login", "success"),
    (r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?$", "ssh_invalid_user", "failure"),
    (r"^error: maximum authentication attempts exceeded for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)", "ssh_max_auth_exceeded", "failure"),
    (r"^Disconnected from (?:(?:invalid|authenticating) )?user (?P<user>.*?) (?P<ip>\S+) port (?P<port>\d+)", "ssh_disconnect", None),
    (r"^Disconnected from (?P<ip>\S+) port (?P<port>\d+)", "ssh_disconnect", None),
    (r"^Received disconnect from (?P<ip>\S+) port (?P<port>\d+)", "ssh_disconnect", None),
    (r"^Connection closed by (?:(?:invalid|authenticating) user (?P<user>.*?) )?(?P<ip>\S+) port (?P<port>\d+)", "ssh_connection_closed", None),
    (r"^Connection from (?P<ip>\S+) port (?P<port>\d+)", "ssh_connection", None),
]
SUDO_RULES = [
    (r"^\s*(?P<user>\S+) : (?P<problem>.*?)TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; USER=(?P<run_as>\S+) ; (?:.*?; )?COMMAND=(?P<command>.*)$", "sudo_command", None),
]
SU_RULES = [
    (r"^(?P<result>Successful|FAILED) su for (?P<target>\S+) by (?P<user>\S+)", "su", None),
]
ACCOUNT_RULES = [
    (r"^new user: name=(?P<user>[^,]+),", "user_created", "success"),
    (r"^new group: name=(?P<group>[^,]+),", "group_created", "success"),
    (r"^delete user '(?P<user>[^']+)'", "user_deleted", "success"),
    (r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'", "user_group_added", "success"),
]
CRON_RULES = [
    (r"^\((?P<user>[^)]+)\) CMD \((?P<command>.*)\)$", "cron_command", None),
]
PAM_RULES = [
    (r"pam_unix\((?P<service>[^:)]+):session\): session (?P<state>opened|closed) for user (?P<user>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<by>[^\s(]*)(?:\(uid=\d+\))?)?", "session", "success"),
    (r"pam_unix\((?P<service>[^:)]+):auth\): authentication failure;(?P<kv>.*)$", "auth_failure", "failure"),
    (r"pam_unix\((?P<service>[^:)]+):chauthtok\): password changed for (?P<user>\S+)", "password_changed", "success"),
]


def _compile(rules: list[tuple[str, str, str | None]]) -> list[tuple[re.Pattern[str], str, str | None]]:
    return [(re.compile(p), a, o) for p, a, o in rules]


SSHD, SUDO, SU, ACCOUNT, CRON, PAM = map(_compile, (SSHD_RULES, SUDO_RULES, SU_RULES, ACCOUNT_RULES, CRON_RULES, PAM_RULES))


def _rules_for(process: str | None) -> list[tuple[re.Pattern[str], str, str | None]]:
    p = (process or "").lower()
    if p.startswith("sshd"):
        return SSHD + PAM
    if p == "sudo":
        return SUDO + PAM
    if p == "su":
        return SU + PAM
    if p in ("useradd", "userdel", "usermod", "groupadd"):
        return ACCOUNT
    if p in ("cron", "crond"):
        return CRON + PAM
    return PAM


def interpret(process: str | None, msg: str) -> dict[str, Any]:
    """Pull user / src_ip / action / outcome out of a known message."""
    for regex, action, outcome in _rules_for(process):
        m = regex.search(msg)
        if not m:
            continue
        g = {k: v for k, v in m.groupdict().items() if v is not None}
        out: dict[str, Any] = {"action": action, "outcome": outcome, "extra": {}}
        extra = out["extra"]

        if action == "session":
            out["action"] = f"session_{g.pop('state')}"
            if g.get("by") == "":
                g.pop("by")
        elif action == "auth_failure":
            kv = dict(re.findall(r"(\w+)=(\S*)", g.pop("kv")))
            g.update({k: v for k, v in kv.items() if v and k in ("user", "ruser", "tty", "logname")})
            if kv.get("rhost"):
                g["ip"] = kv["rhost"]
        elif action == "sudo_command":
            problem = g.pop("problem").strip(" ;")
            out["outcome"] = "failure" if problem else "success"
            if problem:
                extra["problem"] = problem
        elif action == "su":
            out["outcome"] = "success" if g.pop("result") == "Successful" else "failure"
        if "invalid" in g:
            g.pop("invalid")
            extra["invalid_user"] = True

        user = g.pop("user", None)
        out["user"] = (user.strip() or None) if user is not None else None
        ip_text = g.pop("ip", None)
        out["src_ip"] = _ip(ip_text)
        if ip_text and out["src_ip"] is None:
            extra["remote_host"] = ip_text
        if "port" in g:
            extra["src_port"] = int(g.pop("port"))
        extra.update(g)
        return out
    return {}


def _split_tag(body: str) -> tuple[str | None, int | None, str]:
    m = TAG_RE.match(body)
    if not m:
        return None, None, body
    pid = m.group("pid")
    return m.group("proc"), int(pid) if pid else None, m.group("msg")


def _split_host(rest: str) -> tuple[str | None, str]:
    parts = rest.split(None, 1)
    if len(parts) == 2 and HOST_RE.match(parts[0]):
        return parts[0], parts[1]
    return None, rest


def _pri_extra(pri: str | None) -> dict[str, int]:
    if pri is None:
        return {}
    n = int(pri)
    return {"facility": n >> 3, "severity": n & 7}


def _sd_split(rest: str) -> tuple[str | None, str]:
    """Split RFC 5424 STRUCTURED-DATA from MSG."""
    if rest.startswith("-"):
        return None, rest[1:].lstrip(" ")
    if not rest.startswith("["):
        return None, rest
    i, in_quote = 0, False
    while i < len(rest):
        c = rest[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            in_quote = not in_quote
        elif c == "]" and not in_quote and (i + 1 >= len(rest) or rest[i + 1] != "["):
            return rest[: i + 1], rest[i + 1 :].lstrip(" ")
        i += 1
    return rest, ""


def _event(ctx: SourceContext, line_no: int, raw: str, ts_raw: str, ts_utc: datetime,
           host: str | None, process: str | None, pid: int | None, msg: str,
           tz: str, tz_assumed: bool, year_inferred: bool, extra: dict[str, Any]) -> Event:
    info = interpret(process, msg)
    return Event(
        ts_utc=ts_utc,
        ts_raw=ts_raw,
        source_id=ctx.source_id,
        source_type=ctx.source_type,
        source_file=ctx.source_file,
        file_sha256=ctx.file_sha256,
        line_no=line_no,
        raw_line=raw,
        host=host or ctx.host,
        process=process,
        pid=pid,
        user=info.get("user"),
        src_ip=info.get("src_ip"),
        action=info.get("action"),
        outcome=info.get("outcome"),
        message=msg,
        tz=tz,
        tz_assumed=tz_assumed,
        year_inferred=year_inferred,
        extra={**extra, **info.get("extra", {})},
    )


def parse_syslog(ctx: SourceContext) -> ParseResult:
    tz = resolve_tz(ctx.tz)
    result = ParseResult()
    classic: list[tuple[int, str, re.Match[str], tuple[int, int, int, int, int, int]]] = []
    ordered: list[Any] = []  # Event, or index into classic, in file order

    for line_no, raw in read_lines(ctx.evidence_path):
        result.lines += 1
        if not raw.strip():
            result.blank_lines += 1
            continue

        m = RFC5424_RE.match(raw)
        if m:
            if m["ts"] == "-":
                result.gap(ctx, line_no, raw, "RFC 5424 line has no timestamp")
                continue
            try:
                ts = parse_rfc3339(m["ts"])
            except ValueError:
                result.gap(ctx, line_no, raw, f"bad RFC 5424 timestamp {m['ts']!r}")
                continue
            sd, msg = _sd_split(m["rest"])
            extra: dict[str, Any] = _pri_extra(m["pri"])
            ts, zone, assumed = _aware(ts, ctx, tz, extra)
            if m["msgid"] != "-":
                extra["msgid"] = m["msgid"]
            if sd:
                extra["structured_data"] = sd
            procid = m["procid"]
            ordered.append(_event(
                ctx, line_no, raw, m["ts"], to_utc(ts),
                None if m["host"] == "-" else m["host"],
                None if m["app"] == "-" else m["app"],
                int(procid) if procid.isdigit() else None,
                msg.lstrip("\ufeff"), zone, assumed, False, extra,
            ))
            continue

        m = ISO_RE.match(raw)
        if m:
            text = m["ts"].replace(",", ".").replace(" ", "T", 1)
            try:
                ts = parse_rfc3339(text)
            except ValueError:
                result.gap(ctx, line_no, raw, f"bad ISO timestamp {m['ts']!r}")
                continue
            extra = _pri_extra(m["pri"])
            ts, zone, assumed = _aware(ts, ctx, tz, extra)
            host, body = _split_host(m["rest"])
            process, pid, msg = _split_tag(body)
            ordered.append(_event(ctx, line_no, raw, m["ts"], to_utc(ts), host, process, pid,
                                  msg, zone, assumed, False, extra))
            continue

        m = CLASSIC_RE.match(raw)
        if m and m["mon"].lower() in MONTHS:
            stamp = (MONTHS[m["mon"].lower()], int(m["day"]), int(m["h"]), int(m["m"]),
                     int(m["s"]), frac_to_us(m["frac"]))
            ordered.append(len(classic))
            classic.append((line_no, raw, m, stamp))
            continue

        result.gap(ctx, line_no, raw, "no syslog timestamp format matched")

    if classic:
        reference = None
        if ctx.reference_time is not None:
            reference = ctx.reference_time.astimezone(tz).replace(tzinfo=None)
        years = infer_years([c[3] for c in classic], ctx.year, reference)
        if ctx.year is None:
            result.notes.append(
                f"year inferred for {len(classic)} classic syslog lines "
                f"({years[0]}..{years[-1]}) from reference "
                f"{reference.isoformat() if reference else 'current time'}"
            )

    for item in ordered:
        if isinstance(item, Event):
            result.events.append(item)
            continue
        line_no, raw, m, (mon, day, h, mi, s, us) = classic[item]
        try:
            naive = datetime(years[item], mon, day, h, mi, s, us)
        except ValueError:
            result.gap(ctx, line_no, raw, f"invalid date {m['ts']!r} in year {years[item]}")
            continue
        aware, ambiguous = localize(naive, tz)
        extra = _pri_extra(m["pri"])
        if ambiguous:
            extra["dst_ambiguous"] = True
        host, body = _split_host(m["rest"])
        process, pid, msg = _split_tag(body)
        result.events.append(_event(ctx, line_no, raw, m["ts"], to_utc(aware), host, process, pid,
                                    msg, ctx.tz, ctx.tz_assumed, ctx.year is None, extra))
    return result


def _aware(ts: datetime, ctx: SourceContext, tz: Any, extra: dict[str, Any]) -> tuple[datetime, str, bool]:
    """Use the line's own offset if it has one, else the source's zone."""
    if ts.tzinfo is not None:
        return ts, offset_label(ts), False
    ts, ambiguous = localize(ts, tz)
    if ambiguous:
        extra["dst_ambiguous"] = True
    return ts, ctx.tz, ctx.tz_assumed
