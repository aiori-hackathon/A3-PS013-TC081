"""Clock-skew estimation between log sources.

Hosts whose clocks are not synchronised (RFC 5905) record the same moment
at different times, which can put cause after effect. Offsets here are
"seconds the source clock runs ahead of the reference clock": a source
event is corrected by subtracting its source's offset.

Two ways to get an offset:
  * estimate(): automatic. Pairs events from the two sources that share a
    key (by default the client IP) and lie within a search window, then
    finds the tightest cluster of time differences. Unrelated pairs spread
    out across the window while the true skew shows up as a peak, so the
    cluster median is a robust estimate.
  * from_anchor(): manual. The analyst names one line in each source that
    records the same real event.
"""

from __future__ import annotations

import statistics
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Sequence

from .models import Event

DEFAULT_KEYS = ("src_ip",)


@dataclass
class SkewEstimate:
    source_id: str
    reference_id: str
    offset_s: float | None
    matches: int  # pairs inside the winning cluster
    candidate_pairs: int  # all pairs inside the search window
    spread_s: float | None  # median absolute deviation of the cluster
    method: str

    @property
    def usable(self) -> bool:
        return self.offset_s is not None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _key(e: Event, fields: Sequence[str]) -> tuple[Any, ...] | None:
    values = tuple(getattr(e, f) for f in fields)
    return None if any(v in (None, "") for v in values) else values


def _source_ts(e: Event) -> float:
    return e.ts_source_utc.timestamp()


def estimate(
    source: Sequence[Event],
    reference: Sequence[Event],
    match_on: Sequence[str] = DEFAULT_KEYS,
    window_s: float = 3600.0,
    tolerance_s: float = 2.0,
    min_matches: int = 3,
) -> SkewEstimate:
    """Estimate how far `source`'s clock runs ahead of `reference`'s.

    window_s bounds the skew that can be found; tolerance_s is how tightly
    the differences for genuine matches must agree. Both sources' own
    readings are compared (any skew already applied is ignored).
    """
    sid = source[0].source_id if source else "?"
    rid = reference[0].source_id if reference else "?"
    method = f"auto: match on {','.join(match_on)}, window {window_s:g}s, tolerance {tolerance_s:g}s"

    ref_by_key: dict[tuple[Any, ...], list[float]] = defaultdict(list)
    for e in reference:
        k = _key(e, match_on)
        if k is not None:
            ref_by_key[k].append(_source_ts(e))
    for times in ref_by_key.values():
        times.sort()

    deltas: list[float] = []
    for e in source:
        k = _key(e, match_on)
        if k is None or k not in ref_by_key:
            continue
        t = _source_ts(e)
        times = ref_by_key[k]
        lo = bisect_left(times, t - window_s)
        hi = bisect_right(times, t + window_s)
        deltas.extend(t - r for r in times[lo:hi])

    if not deltas:
        return SkewEstimate(sid, rid, None, 0, 0, None, method)

    deltas.sort()
    best_i, best_j = 0, 0
    j = 0
    for i in range(len(deltas)):
        while j + 1 < len(deltas) and deltas[j + 1] - deltas[i] <= tolerance_s:
            j += 1
        if j - i > best_j - best_i:
            best_i, best_j = i, j
    cluster = deltas[best_i : best_j + 1]
    if len(cluster) < min_matches:
        return SkewEstimate(sid, rid, None, len(cluster), len(deltas), None, method)

    offset = statistics.median(cluster)
    spread = statistics.median(abs(d - offset) for d in cluster)
    return SkewEstimate(sid, rid, round(offset, 6), len(cluster), len(deltas), round(spread, 6), method)


def from_anchor(source_event: Event, reference_event: Event) -> SkewEstimate:
    """Offset from one pair of lines the analyst says are the same event."""
    offset = _source_ts(source_event) - _source_ts(reference_event)
    return SkewEstimate(
        source_event.source_id,
        reference_event.source_id,
        round(offset, 6),
        1,
        1,
        0.0,
        f"anchor: {source_event.event_id} = {reference_event.event_id}",
    )
