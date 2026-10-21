import random
from datetime import datetime, timedelta, timezone

import pytest

from incident_timeline.models import Event
from incident_timeline.skew import estimate, from_anchor

T0 = datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc)


def ev(source_id, seconds, ip, line_no=1, user=None):
    return Event(T0 + timedelta(seconds=seconds), "", source_id, "syslog", "f", "0" * 64, line_no, "",
                 src_ip=ip, user=user)


def paired_logs(skew_s, n=20, noise_s=0.4, seed=7):
    """Reference and source logs recording the same n events, plus unrelated noise."""
    rng = random.Random(seed)
    ref, src = [], []
    for i in range(n):
        t = i * 37.0
        ip = f"10.0.0.{i % 4 + 1}"
        ref.append(ev("S001", t, ip, i + 1))
        src.append(ev("S002", t + skew_s + rng.uniform(-noise_s, noise_s), ip, i + 1))
    for i in range(10):  # events only one side saw
        src.append(ev("S002", rng.uniform(0, 800), f"10.0.0.{rng.randint(1, 4)}", 100 + i))
    return src, ref


@pytest.mark.parametrize("skew_s", [0.0, 95.0, -300.0, 1234.5])
def test_estimate_recovers_known_skew(skew_s):
    src, ref = paired_logs(skew_s)
    est = estimate(src, ref, window_s=3600)
    assert est.usable
    assert est.offset_s == pytest.approx(skew_s, abs=0.5)
    assert est.matches >= 15 and est.source_id == "S002" and est.reference_id == "S001"


def test_estimate_ignores_already_applied_skew():
    src, ref = paired_logs(120.0)
    for e in src:
        e.apply_skew(50.0)
    assert estimate(src, ref).offset_s == pytest.approx(120.0, abs=0.5)


def test_no_shared_keys_gives_no_estimate():
    ref = [ev("S001", i, "10.0.0.1") for i in range(5)]
    src = [ev("S002", i, "192.168.1.1") for i in range(5)]
    est = estimate(src, ref)
    assert not est.usable and est.candidate_pairs == 0


def test_too_few_matches_gives_no_estimate():
    ref = [ev("S001", 0, "10.0.0.1")]
    src = [ev("S002", 30, "10.0.0.1")]
    assert estimate(src, ref, min_matches=3).offset_s is None


def test_skew_outside_window_is_not_found():
    src, ref = paired_logs(5000.0)
    assert estimate(src, ref, window_s=600).offset_s is None


def test_match_on_multiple_fields():
    ref = [ev("S001", i * 60, "10.0.0.1", user=u) for i, u in enumerate(["a", "b", "c", "d"])]
    src = [ev("S002", i * 60 + 10, "10.0.0.1", user=u) for i, u in enumerate(["a", "b", "c", "d"])]
    est = estimate(src, ref, match_on=("src_ip", "user"), tolerance_s=0.5)
    assert est.offset_s == 10 and est.candidate_pairs == 4


def test_anchor_and_apply():
    src_event = ev("S002", 100, "10.0.0.1", line_no=12)
    ref_event = ev("S001", 40, "10.0.0.1", line_no=3)
    est = from_anchor(src_event, ref_event)
    assert est.offset_s == 60 and est.method == "anchor: S002:12 = S001:3"

    src_event.apply_skew(est.offset_s)
    assert src_event.ts_utc == ref_event.ts_utc
    assert src_event.ts_source_utc == T0 + timedelta(seconds=100)
