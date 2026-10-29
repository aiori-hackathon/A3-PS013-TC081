"""Log parsers. Each takes a SourceContext and returns a ParseResult.

Parsers never drop a line: every non-blank line becomes either an Event or
a ParseGap.
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from ..models import Event, ParseGap, SourceContext


@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    gaps: list[ParseGap] = field(default_factory=list)
    lines: int = 0
    blank_lines: int = 0
    notes: list[str] = field(default_factory=list)
    rule_events: dict[str, int] = field(default_factory=dict)  # events added per parser rule

    def gap(self, ctx: SourceContext, line_no: int, raw: str, reason: str) -> None:
        self.gaps.append(ParseGap(ctx.source_id, ctx.source_file, ctx.file_sha256, line_no, raw, reason))


def read_lines(path: Path) -> Iterator[tuple[int, str]]:
    """Yield (line_no, text) from a log, transparently reading .gz files.

    Bytes that are not valid UTF-8 are kept as \\xNN escapes so the raw line
    still shows exactly what was on disk.
    """
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as fh:
        for i, raw in enumerate(fh, start=1):
            raw = raw.rstrip(b"\n").rstrip(b"\r")
            yield i, raw.decode("utf-8", errors="backslashreplace")


def parse_custom(ctx: SourceContext) -> ParseResult:
    """A format with no built-in parser: every line is kept as a gap until a parser rule covers it."""
    result = ParseResult()
    for line_no, raw in read_lines(ctx.evidence_path):
        result.lines += 1
        if not raw.strip():
            result.blank_lines += 1
            continue
        result.gap(ctx, line_no, raw, "no built-in parser for this format; add a parser rule")
    return result


def get_parser(source_type: str) -> Callable[[SourceContext], ParseResult]:
    from .access import parse_access
    from .syslog import parse_syslog

    parsers = {"syslog": parse_syslog, "access": parse_access, "custom": parse_custom}
    try:
        return parsers[source_type]
    except KeyError:
        raise ValueError(f"no parser for source type {source_type!r}") from None


def parse_source(ctx: SourceContext) -> ParseResult:
    return get_parser(ctx.source_type)(ctx)
