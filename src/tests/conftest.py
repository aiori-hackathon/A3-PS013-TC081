from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

import pytest

from incident_timeline.models import SourceContext

DATA = Path(__file__).parent / "data"


@pytest.fixture
def make_ctx(tmp_path):
    """Build a SourceContext over a temporary log made of the given lines."""

    def _make(lines: list[str] | None = None, *, sample: str | None = None,
              source_type: str = "syslog", tz: str = "UTC", tz_assumed: bool = False,
              year: int | None = None, reference: datetime | None = None,
              host: str | None = None, source_id: str = "S001") -> SourceContext:
        path = tmp_path / f"{source_id}.log"
        if sample:
            shutil.copyfile(DATA / sample, path)
        else:
            path.write_text("\n".join(lines or []) + "\n", encoding="utf-8")
        return SourceContext(source_id, source_type, path.name, path, "0" * 64, tz=tz,
                             tz_assumed=tz_assumed, host=host, year=year, reference_time=reference)

    return _make
