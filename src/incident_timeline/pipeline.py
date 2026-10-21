"""Parse every collected source and build the merged UTC timeline.

Outputs, in CASE/normalised/:
  events.jsonl   one Event per parsed line, sorted by corrected UTC time
  gaps.jsonl     every line no parser understood, with the reason
  summary.json   per-source counts, zones, skew offsets and notes
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence

from .evidence import Case, EvidenceError, check_source, sha256_file
from .models import Event, SourceContext, write_jsonl
from .parsers import ParseResult, parse_source
from .skew import DEFAULT_KEYS, SkewEstimate, estimate, from_anchor
from .timeutil import UTC, parse_rfc3339, to_rfc3339


def source_context(case: Case, s: dict[str, Any]) -> SourceContext:
    return SourceContext(
        source_id=s["source_id"],
        source_type=s["source_type"],
        source_file=s["original_name"],
        evidence_path=case.root / s["evidence_path"],
        file_sha256=s["sha256"],
        tz=s.get("tz") or "UTC",
        tz_assumed=bool(s.get("tz_assumed", True)),
        host=s.get("host"),
        year=s.get("year"),
        reference_time=parse_rfc3339(s["original_mtime_utc"]) if s.get("original_mtime_utc") else None,
    )


def parse_sources(case: Case, source_ids: Sequence[str] | None = None,
                  force: bool = False) -> dict[str, ParseResult]:
    """Parse the evidence copies, after checking each still matches its hash.

    Skew offsets from case.json are applied to the returned events.
    """
    results: dict[str, ParseResult] = {}
    for s in case.sources():
        if source_ids is not None and s["source_id"] not in source_ids:
            continue
        problem = check_source(case, s["source_id"])
        if problem and not force:
            raise EvidenceError(f"{problem}; refusing to parse (run verify)")
        result = parse_source(source_context(case, s))
        offset = float(s.get("skew_offset_s") or 0.0)
        if offset:
            for e in result.events:
                e.apply_skew(offset)
        results[s["source_id"]] = result
    if source_ids is not None:
        missing = set(source_ids) - set(results)
        if missing:
            raise EvidenceError(f"unknown source(s): {', '.join(sorted(missing))}")
    return results


def merge(results: dict[str, ParseResult]) -> list[Event]:
    events = [e for r in results.values() for e in r.events]
    events.sort(key=lambda e: (e.ts_utc, e.source_id, e.line_no))
    return events


@dataclass
class BuildOutput:
    events: list[Event]
    summary: dict[str, Any]


def build_timeline(case: Case, actor: str | None = None, force: bool = False) -> BuildOutput:
    results = parse_sources(case, force=force)
    events = merge(results)
    gaps = sorted((g for r in results.values() for g in r.gaps), key=lambda g: (g.source_id, g.line_no))

    out = case.output_dir
    write_jsonl(out / "events.jsonl", events)
    write_jsonl(out / "gaps.jsonl", gaps)

    per_source = []
    for s in case.sources():
        r = results[s["source_id"]]
        evs = r.events
        content = r.lines - r.blank_lines
        per_source.append({
            "source_id": s["source_id"],
            "source_type": s["source_type"],
            "source_file": s["original_name"],
            "sha256": s["sha256"],
            "host": s.get("host"),
            "tz": s.get("tz"),
            "skew_offset_s": s.get("skew_offset_s") or 0.0,
            "skew_method": s.get("skew_method"),
            "lines": r.lines,
            "blank_lines": r.blank_lines,
            "events": len(evs),
            "gaps": len(r.gaps),
            "parsed_ratio": round(len(evs) / content, 4) if content else None,
            "first_ts_utc": to_rfc3339(min(e.ts_utc for e in evs)) if evs else None,
            "last_ts_utc": to_rfc3339(max(e.ts_utc for e in evs)) if evs else None,
            "year_inferred_events": sum(e.year_inferred for e in evs),
            "tz_assumed_events": sum(e.tz_assumed for e in evs),
            "dst_ambiguous_events": sum(bool(e.extra.get("dst_ambiguous")) for e in evs),
            "actions": dict(Counter(e.action for e in evs if e.action).most_common()),
            "gap_reasons": dict(Counter(g.reason for g in r.gaps).most_common()),
            "notes": r.notes,
        })

    summary = {
        "case_id": case.load_meta().get("case_id"),
        "generated_utc": to_rfc3339(datetime.now(UTC)),
        "events": len(events),
        "gaps": len(gaps),
        "first_ts_utc": to_rfc3339(events[0].ts_utc) if events else None,
        "last_ts_utc": to_rfc3339(events[-1].ts_utc) if events else None,
        "sources": per_source,
    }
    with open(out / "summary.json", "w", encoding="utf-8", newline="\n") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    outputs = {}
    for name in ("events.jsonl", "gaps.jsonl", "summary.json"):
        digest, _ = sha256_file(out / name)
        outputs[f"normalised/{name}"] = digest
    case.append_custody(
        "parse",
        actor,
        sources={s["source_id"]: s["sha256"] for s in case.sources()},
        outputs=outputs,
        events=len(events),
        gaps=len(gaps),
    )
    return BuildOutput(events, summary)


def estimate_case_skew(
    case: Case,
    reference_id: str,
    match_on: Sequence[str] = DEFAULT_KEYS,
    window_s: float = 3600.0,
    tolerance_s: float = 2.0,
    min_matches: int = 3,
) -> list[SkewEstimate]:
    """Estimate every other source's offset against reference_id."""
    results = parse_sources(case)
    if reference_id not in results:
        raise EvidenceError(f"unknown reference source {reference_id!r}")
    ref = results[reference_id].events
    return [
        estimate(r.events, ref, match_on, window_s, tolerance_s, min_matches)
        for sid, r in results.items()
        if sid != reference_id and r.events
    ]


def anchor_skew(case: Case, source_line: tuple[str, int], reference_line: tuple[str, int]) -> SkewEstimate:
    """Offset from two lines (source_id, line_no) that record the same event."""
    results = parse_sources(case, [source_line[0], reference_line[0]])

    def find(sid: str, line_no: int) -> Event:
        for e in results[sid].events:
            if e.line_no == line_no:
                return e
        raise EvidenceError(f"{sid} line {line_no} is not a parsed event")

    return from_anchor(find(*source_line), find(*reference_line))


def apply_skew(case: Case, est: SkewEstimate, actor: str | None = None) -> None:
    """Store an offset in case.json and record who set it and how."""
    if est.offset_s is None:
        raise ValueError(f"no usable offset for {est.source_id}")
    case.update_source(est.source_id, skew_offset_s=est.offset_s, skew_method=est.method,
                       skew_reference=est.reference_id)
    case.append_custody("set_skew", actor, **est.to_dict())
