"""Time zone resolution, local-to-UTC conversion and RFC 3339 formatting."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC = timezone.utc

MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_OFFSET_RE = re.compile(r"^(?:UTC|GMT)?([+-])(\d{2}):?(\d{2})$", re.IGNORECASE)


def resolve_tz(spec: str) -> tzinfo:
    """Turn a zone spec into a tzinfo.

    Accepts "UTC"/"Z", fixed offsets ("+05:30", "-0800", "UTC+05:30") and
    IANA names ("Asia/Kolkata"). IANA names follow daylight-saving rules;
    fixed offsets do not.
    """
    s = spec.strip()
    if s.upper() in ("UTC", "Z", "GMT"):
        return UTC
    m = _OFFSET_RE.match(s)
    if m:
        sign, hh, mm = m.groups()
        delta = timedelta(hours=int(hh), minutes=int(mm))
        if delta >= timedelta(hours=24):
            raise ValueError(f"offset out of range: {spec!r}")
        return timezone(-delta if sign == "-" else delta)
    try:
        return ZoneInfo(s)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown time zone: {spec!r}") from exc


def parse_offset(text: str) -> timezone:
    """Parse a numeric UTC offset such as "+0530" or "-08:00"."""
    m = _OFFSET_RE.match(text.strip())
    if not m:
        raise ValueError(f"bad UTC offset: {text!r}")
    sign, hh, mm = m.groups()
    delta = timedelta(hours=int(hh), minutes=int(mm))
    return timezone(-delta if sign == "-" else delta)


def localize(naive: datetime, tz: tzinfo) -> tuple[datetime, bool]:
    """Attach tz to a naive local time.

    Returns (aware datetime, dst_ambiguous). dst_ambiguous is True when the
    wall-clock time is repeated or skipped by a daylight-saving change, so
    the UTC instant cannot be known for certain; the earlier reading
    (fold=0) is used.
    """
    first = naive.replace(tzinfo=tz, fold=0)
    second = naive.replace(tzinfo=tz, fold=1)
    return first, first.utcoffset() != second.utcoffset()


def offset_label(dt: datetime) -> str:
    """Offset label such as "+05:30" for an aware datetime, or "UTC" for zero."""
    off = dt.utcoffset()
    if not off:
        return "UTC"
    total = int(off.total_seconds())
    sign = "-" if total < 0 else "+"
    total = abs(total)
    return f"{sign}{total // 3600:02d}:{total % 3600 // 60:02d}"


def to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise ValueError("naive datetime cannot be converted to UTC")
    return dt.astimezone(UTC)


def to_rfc3339(dt: datetime) -> str:
    """Format as RFC 3339 UTC, e.g. 2026-10-12T08:07:01Z."""
    u = to_utc(dt)
    spec = "microseconds" if u.microsecond else "seconds"
    return u.isoformat(timespec=spec).replace("+00:00", "Z")


def parse_rfc3339(text: str) -> datetime:
    """Parse an ISO 8601 / RFC 3339 timestamp (with offset or Z)."""
    s = text.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)
    # fromisoformat on 3.11 accepts at most 6 fractional digits.
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    return datetime.fromisoformat(s)


def frac_to_us(frac: str | None) -> int:
    """Convert a fractional-seconds digit string to microseconds."""
    if not frac:
        return 0
    return int((frac + "000000")[:6])
