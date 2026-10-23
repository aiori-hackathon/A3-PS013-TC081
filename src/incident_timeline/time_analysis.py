"""Explainable timestamp-basis diagnostics and read-only clock-offset previews.

This module deliberately does not assign a confidence percentage. It reports
only values already present in normalized events/case metadata, and exact
cross-source timestamp ties. Offset previews are calculated in memory and
never update the case, events, evidence, or custody records.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Sequence

from .models import Event
from .timeutil import to_rfc3339

_MAX_PREVIEW_OFFSET_S = 31_536_000.0  # one year; guards accidental extreme input
_SECONDS_RE = re.compile(r"(?:T|:|\s)\d{1,2}:\d{2}:(\d{2})(?:[.,](\d{1,9}))?")
_MINUTE_RE = re.compile(r"(?:T|:|\s)\d{1,2}:\d{2}(?:Z|[+-]\d{2}(?::?\d{2})?)?$", re.IGNORECASE)
_DATE_RE = re.compile(r"^\s*\d{4}-\d{2}-\d{2}(?:$|[Tt\s])")


def _number(value: Any, default: float = 0.0) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    return n if math.isfinite(n) else default


def _event_flags(event: Event) -> list[str]:
    flags: list[str] = []
    if event.tz_assumed:
        flags.append("timezone_assumed")
    if event.year_inferred:
        flags.append("year_inferred")
    if bool(event.extra.get("dst_ambiguous")):
        flags.append("dst_ambiguous")
    if abs(_number(event.skew_offset_s)) > 0.0000005:
        flags.append("clock_offset_applied")
    return flags


def _precision(ts_raw: str) -> tuple[float | None, str]:
    """Describe the precision visible in the literal timestamp text.

    The parser stores datetimes at microsecond precision. For formats whose
    textual precision cannot be identified safely, report it as unknown rather
    than implying that missing components were recorded.
    """
    raw = ts_raw or ""
    seconds = _SECONDS_RE.search(raw)
    if seconds:
        fraction = seconds.group(2)
        if fraction:
            digits = len(fraction)
            effective_digits = min(digits, 6)  # datetime stores microseconds
            resolution = {1: "100 ms", 2: "10 ms", 3: "1 ms", 4: "100 µs", 5: "10 µs", 6: "1 µs"}[effective_digits]
            return 10 ** -effective_digits, f"{digits} fractional digit{'s' if digits != 1 else ''} recorded; parser resolution is {resolution}"
        return 1.0, "Seconds recorded; no fractional part"
    if _MINUTE_RE.search(raw):
        return 60.0, "Minute-level timestamp; seconds omitted"
    if _DATE_RE.match(raw):
        return 86400.0, "Date-level timestamp; time omitted"
    return None, "Source text precision not classified"


def _current_ties(events: Sequence[Event], time_for) -> list[dict[str, Any]]:
    by_instant: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_instant[to_rfc3339(time_for(event))].append(event)
    ties = []
    for instant, group in by_instant.items():
        source_ids = sorted({e.source_id for e in group})
        if len(source_ids) < 2:
            continue
        ties.append({
            "timestamp_utc": instant,
            "event_count": len(group),
            "source_count": len(source_ids),
            "source_ids": source_ids,
            "events": [{
                "event_id": e.event_id,
                "source_id": e.source_id,
                "source_file": e.source_file,
                "line_no": e.line_no,
                "action": e.action or "Unclassified event",
                "raw_timestamp": e.ts_raw,
                "timezone": e.tz,
                "timezone_assumed": bool(e.tz_assumed),
                "year_inferred": bool(e.year_inferred),
                "dst_ambiguous": bool(e.extra.get("dst_ambiguous")),
            } for e in sorted(group, key=lambda item: (item.source_id, item.line_no))[:8]],
        })
    ties.sort(key=lambda item: item["timestamp_utc"])
    return ties


def build_time_analysis(
    case: Any,
    events: Sequence[Event],
    *,
    limit: int = 100,
    offset: int = 0,
    source_filter: str | None = None,
    issues_only: bool = False,
    preview_source_id: str | None = None,
    preview_offset_s: float | None = None,
) -> dict[str, Any]:
    """Build explainable time diagnostics and an optional, non-persistent preview.

    `preview_offset_s` is the proposed absolute offset for `preview_source_id`.
    By engine convention, a positive offset means the source clock was ahead;
    that offset is subtracted from the source timestamp to produce UTC.
    """
    if not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError("limit must be an integer from 1 to 200")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative integer")

    source_meta = list(case.sources())
    sources_by_id = {str(source.get("source_id")): source for source in source_meta}
    if source_filter and source_filter not in sources_by_id:
        raise ValueError(f"unknown source filter {source_filter!r}")
    preview_active = preview_source_id is not None or preview_offset_s is not None
    if preview_active:
        if not preview_source_id or preview_source_id not in sources_by_id:
            raise ValueError("preview_source_id must name a source in this case")
        if preview_offset_s is None or not math.isfinite(float(preview_offset_s)):
            raise ValueError("preview_offset_s must be a finite number of seconds")
        preview_offset_s = float(preview_offset_s)
        if abs(preview_offset_s) > _MAX_PREVIEW_OFFSET_S:
            raise ValueError("preview_offset_s must be within ±31,536,000 seconds")

    events_list = list(events)
    events_by_source: dict[str, list[Event]] = defaultdict(list)
    for event in events_list:
        events_by_source[event.source_id].append(event)

    # The currently stored, corrected timeline is the immutable comparison base.
    current_sorted = sorted(events_list, key=lambda e: (e.ts_utc, e.source_id, e.line_no))
    current_rank = {event.event_id: index for index, event in enumerate(current_sorted, start=1)}

    def preview_time(event: Event) -> datetime:
        if preview_active and event.source_id == preview_source_id:
            return event.ts_source_utc - timedelta(seconds=float(preview_offset_s))
        return event.ts_utc

    if preview_active:
        preview_sorted = sorted(events_list, key=lambda e: (preview_time(e), e.source_id, e.line_no))
    else:
        preview_sorted = current_sorted
    preview_rank = {event.event_id: index for index, event in enumerate(preview_sorted, start=1)}

    # These groups are exact ties in the stored timestamps, not a claim that
    # the underlying events happened simultaneously or were causally linked.
    current_ties = _current_ties(events_list, lambda e: e.ts_utc)
    displayed_ties = _current_ties(events_list, preview_time if preview_active else lambda e: e.ts_utc)

    source_cards: list[dict[str, Any]] = []
    source_map = {str(s.get("source_id")): s for s in source_meta}
    for source_id in sorted(source_map):
        source = source_map[source_id]
        source_events = events_by_source.get(source_id, [])
        recorded_offsets = sorted({round(_number(e.skew_offset_s), 6) for e in source_events})
        applied_offset = recorded_offsets[0] if len(recorded_offsets) == 1 else None
        configured_offset = _number(source.get("skew_offset_s"))
        if len(recorded_offsets) > 1:
            # A source normally has one configured correction. Mixed per-event
            # values merit review even if one happens to match case metadata.
            offsets_match = False
        elif applied_offset is not None and source_events:
            offsets_match = abs(applied_offset - configured_offset) <= 0.0000005
        else:
            offsets_match = None
        source_events_time = sorted(source_events, key=lambda e: (e.ts_utc, e.line_no))
        source_cards.append({
            "source_id": source_id,
            "source_file": source.get("original_name", source_id),
            "source_type": source.get("source_type", "log"),
            "host": source.get("host"),
            "configured_timezone": source.get("tz") or "UTC",
            "timezone_setting_assumed": (bool(source["tz_assumed"]) if "tz_assumed" in source else None),
            "configured_offset_s": configured_offset,
            "applied_offset_s": applied_offset,
            "recorded_offset_values_s": recorded_offsets,
            "skew_method": source.get("skew_method"),
            "offset_settings_match": offsets_match,
            "event_count": len(source_events),
            "timezone_assumed_events": sum(bool(e.tz_assumed) for e in source_events),
            "year_inferred_events": sum(bool(e.year_inferred) for e in source_events),
            "dst_ambiguous_events": sum(bool(e.extra.get("dst_ambiguous")) for e in source_events),
            "first_timestamp_utc": to_rfc3339(source_events_time[0].ts_utc) if source_events_time else None,
            "last_timestamp_utc": to_rfc3339(source_events_time[-1].ts_utc) if source_events_time else None,
        })

    timezone_assumed = sum(bool(e.tz_assumed) for e in events_list)
    year_inferred = sum(bool(e.year_inferred) for e in events_list)
    dst_ambiguous = sum(bool(e.extra.get("dst_ambiguous")) for e in events_list)
    flagged_events = sum(bool(e.tz_assumed or e.year_inferred or e.extra.get("dst_ambiguous")) for e in events_list)
    offset_sources = sum(
        bool(es) and any(abs(_number(e.skew_offset_s)) > 0.0000005 for e in es)
        for es in events_by_source.values()
    )
    settings_mismatch_sources = sum(s["offset_settings_match"] is False for s in source_cards)

    analysis_summary = {
        "event_count": len(events_list),
        "source_count": len(source_meta),
        "events_flagged_for_time_review": flagged_events,
        "timezone_assumed_events": timezone_assumed,
        "year_inferred_events": year_inferred,
        "dst_ambiguous_events": dst_ambiguous,
        "sources_with_nonzero_applied_offset": offset_sources,
        "sources_where_settings_differ_from_parsed_timeline": settings_mismatch_sources,
        "exact_cross_source_timestamp_tie_groups": len(current_ties),
        "method_note": (
            "These are recorded flags and exact timestamp ties, not a statistical confidence score. "
            "An exact tie means stored normalized timestamps are identical across sources; timestamp order alone does not establish causality."
        ),
    }

    filtered: list[Event] = []
    selected_order = preview_sorted if preview_active else current_sorted
    for event in selected_order:
        if source_filter and event.source_id != source_filter:
            continue
        flags = _event_flags(event)
        if issues_only and not any(flag in flags for flag in ("timezone_assumed", "year_inferred", "dst_ambiguous")):
            continue
        filtered.append(event)

    def event_record(event: Event) -> dict[str, Any]:
        precision_s, precision_label = _precision(event.ts_raw)
        preview_dt = preview_time(event) if preview_active else None
        flags = _event_flags(event)
        return {
            "event_id": event.event_id,
            "source_id": event.source_id,
            "source_file": event.source_file,
            "source_type": event.source_type,
            "line_no": event.line_no,
            "action": event.action or "Unclassified event",
            "outcome": event.outcome,
            "raw_timestamp": event.ts_raw,
            "timezone": event.tz,
            "timezone_assumed": bool(event.tz_assumed),
            "year_inferred": bool(event.year_inferred),
            "dst_ambiguous": bool(event.extra.get("dst_ambiguous")),
            "timestamp_precision_s": precision_s,
            "timestamp_precision_label": precision_label,
            "interpreted_source_utc": to_rfc3339(event.ts_source_utc),
            "normalized_utc": to_rfc3339(event.ts_utc),
            "recorded_offset_s": _number(event.skew_offset_s),
            "preview_utc": to_rfc3339(preview_dt) if preview_dt is not None else None,
            "current_rank": current_rank[event.event_id],
            "preview_rank": preview_rank[event.event_id],
            "position_changed": current_rank[event.event_id] != preview_rank[event.event_id],
            "flags": flags,
        }

    page = filtered[offset:offset + limit]
    tie_groups_for_response = displayed_ties[:20]
    preview_info = None
    if preview_active:
        selected_events = events_by_source.get(str(preview_source_id), [])
        applied_offsets = sorted({round(_number(e.skew_offset_s), 6) for e in selected_events})
        applied_offset = applied_offsets[0] if len(applied_offsets) == 1 else None
        preview_info = {
            "active": True,
            "source_id": preview_source_id,
            "proposed_offset_s": float(preview_offset_s),
            "recorded_timeline_offset_s": applied_offset,
            "configured_offset_s": _number(sources_by_id[str(preview_source_id)].get("skew_offset_s")),
            "events_from_source_with_recalculated_time": len(selected_events),
            "records_shifted_in_merged_order": sum(current_rank[e.event_id] != preview_rank[e.event_id] for e in events_list),
            "exact_cross_source_timestamp_tie_groups_after_preview": len(displayed_ties),
            "persistent_changes_made": False,
        }

    return {
        "case_id": case.load_meta().get("case_id", case.root.name),
        "summary": analysis_summary,
        "sources": source_cards,
        "events": [event_record(event) for event in page],
        "pagination": {
            "offset": offset,
            "limit": limit,
            "filtered_total": len(filtered),
            "has_previous": offset > 0,
            "has_next": offset + limit < len(filtered),
        },
        "timestamp_ties": {
            "total_groups": len(displayed_ties),
            "groups_shown": len(tie_groups_for_response),
            "groups": tie_groups_for_response,
            "basis": "temporary preview" if preview_active else "stored normalized timeline",
        },
        "preview": preview_info,
    }
