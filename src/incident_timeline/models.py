"""Records shared by every stage: parsed events and parsing gaps.

The JSON produced by Event.to_dict() is the contract with the timeline
viewer and report exporter: one object per line in events.jsonl.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from .timeutil import parse_rfc3339, to_rfc3339


@dataclass
class SourceContext:
    """What a parser needs to know about the file it is reading."""

    source_id: str
    source_type: str
    source_file: str  # original file name, for display and citation
    evidence_path: Path  # read-only copy that is actually parsed
    file_sha256: str
    tz: str = "UTC"
    tz_assumed: bool = True  # True when nobody stated the zone
    host: str | None = None
    year: int | None = None  # explicit year for logs that lack one
    reference_time: datetime | None = None  # upper bound for year inference


@dataclass
class Event:
    """One parsed log line.

    ts_utc is the corrected instant: the source's own reading converted to
    UTC, minus skew_offset_s (seconds the source clock runs ahead of the
    reference clock).
    """

    ts_utc: datetime
    ts_raw: str
    source_id: str
    source_type: str
    source_file: str
    file_sha256: str
    line_no: int
    raw_line: str
    host: str | None = None
    process: str | None = None
    pid: int | None = None
    user: str | None = None
    src_ip: str | None = None
    action: str | None = None
    outcome: str | None = None
    message: str | None = None
    tz: str = "UTC"
    tz_assumed: bool = False
    year_inferred: bool = False
    skew_offset_s: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def event_id(self) -> str:
        return f"{self.source_id}:{self.line_no}"

    @property
    def ts_source_utc(self) -> datetime:
        """The source's reading in UTC, before skew correction."""
        return self.ts_utc + timedelta(seconds=self.skew_offset_s)

    def apply_skew(self, offset_s: float) -> None:
        """Replace any earlier correction with offset_s."""
        source = self.ts_source_utc
        self.skew_offset_s = float(offset_s)
        self.ts_utc = source - timedelta(seconds=self.skew_offset_s)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d = {"event_id": self.event_id, **d}
        d["ts_utc"] = to_rfc3339(self.ts_utc)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        d = dict(d)
        d.pop("event_id", None)
        d["ts_utc"] = parse_rfc3339(d["ts_utc"])
        return cls(**d)


@dataclass
class ParseGap:
    """A line no parser rule understood. Kept, never dropped."""

    source_id: str
    source_file: str
    file_sha256: str
    line_no: int
    raw_line: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_jsonl(path: Path, records: list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(json.dumps(r.to_dict(), ensure_ascii=False, sort_keys=False))
            fh.write("\n")


def load_events(path: Path | str) -> Iterator[Event]:
    """Read events.jsonl back into Event objects."""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield Event.from_dict(json.loads(line))
