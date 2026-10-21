from datetime import datetime, timedelta

import pytest

from incident_timeline.timeutil import (
    localize, offset_label, parse_rfc3339, resolve_tz, to_rfc3339,
)


@pytest.mark.parametrize("spec, hours", [
    ("UTC", 0), ("Z", 0), ("+05:30", 5.5), ("+0530", 5.5), ("-08:00", -8), ("UTC+05:45", 5.75),
])
def test_resolve_fixed_offsets(spec, hours):
    assert resolve_tz(spec).utcoffset(None) == timedelta(hours=hours)


def test_resolve_iana_zone():
    tz = resolve_tz("Asia/Kolkata")
    assert datetime(2026, 10, 12, tzinfo=tz).utcoffset() == timedelta(hours=5, minutes=30)


@pytest.mark.parametrize("bad", ["Mars/Olympus", "+25:00", ""])
def test_resolve_rejects_bad_zones(bad):
    with pytest.raises(ValueError):
        resolve_tz(bad)


def test_rfc3339_matches_proposal_example():
    ist = resolve_tz("+05:30")
    assert to_rfc3339(datetime(2026, 10, 12, 13, 37, 1, tzinfo=ist)) == "2026-10-12T08:07:01Z"


def test_rfc3339_keeps_microseconds():
    dt = datetime(2026, 1, 1, 0, 0, 0, 120000, tzinfo=resolve_tz("UTC"))
    assert to_rfc3339(dt) == "2026-01-01T00:00:00.120000Z"


def test_rfc3339_rejects_naive():
    with pytest.raises(ValueError):
        to_rfc3339(datetime(2026, 1, 1))


@pytest.mark.parametrize("text, expected", [
    ("2026-10-12T08:07:01Z", "2026-10-12T08:07:01Z"),
    ("2026-10-12T13:37:01+0530", "2026-10-12T08:07:01Z"),
    ("2026-10-12T13:37:01.123456789+05:30", "2026-10-12T08:07:01.123456Z"),
])
def test_parse_rfc3339(text, expected):
    assert to_rfc3339(parse_rfc3339(text)) == expected


def test_localize_flags_dst_overlap_and_gap():
    ny = resolve_tz("America/New_York")
    _, repeated = localize(datetime(2026, 11, 1, 1, 30), ny)  # clocks fall back
    _, skipped = localize(datetime(2026, 3, 8, 2, 30), ny)  # clocks spring forward
    aware, normal = localize(datetime(2026, 7, 1, 12, 0), ny)
    assert repeated and skipped and not normal
    assert to_rfc3339(aware) == "2026-07-01T16:00:00Z"


def test_offset_label():
    assert offset_label(datetime(2026, 1, 1, tzinfo=resolve_tz("-03:30"))) == "-03:30"
    assert offset_label(datetime(2026, 1, 1, tzinfo=resolve_tz("UTC"))) == "UTC"
