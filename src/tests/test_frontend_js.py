"""The browser-side engines (time-zone matching, theme reveal geometry), run under Node when it is installed."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1] / "incident_timeline"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")


def _node(script: str) -> object:
    out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, check=True, timeout=60)
    return json.loads(out.stdout)


def test_scripts_parse() -> None:
    for name in ("tzpicker.js", "casestore.js", "themereveal.js"):
        subprocess.run([NODE, "--check", str(PKG / name)], check=True, timeout=60)


def test_time_zone_engine_resolves_what_people_type() -> None:
    cases = {"kolkatta": "Asia/Kolkata", "IST": "Asia/Kolkata", "howrah": "Asia/Kolkata", "+5:30": "+05:30",
             "gmt+0530": "+05:30", "utc": "UTC", "pst": "America/Los_Angeles", "nyc": "America/New_York",
             "singapre": "Asia/Singapore", "germany": "Europe/Berlin", "zzzz": None}
    got = _node(f"const tz=require({json.dumps(str(PKG / 'tzpicker.js'))});"
                f"console.log(JSON.stringify(Object.fromEntries({json.dumps(list(cases))}.map(q=>[q,tz.resolve(q)]))))")
    assert got == cases


def test_reveal_starts_at_the_button_and_ends_past_every_corner() -> None:
    w, h, cx, cy = 1280, 800, 1200, 30
    frames = _node(f"const t=require({json.dumps(str(PKG / 'themereveal.js'))});"
                   f"console.log(JSON.stringify(t.revealFrames({cx},{cy},{w},{h},7)))")
    assert len(frames) == 25

    def points(poly: str) -> list[tuple[float, float]]:
        return [tuple(float(v.removesuffix("px")) for v in p.split()) for p in poly[len("polygon("):-1].split(", ")]

    first, last = points(frames[0]), points(frames[-1])
    assert len(first) == 180 and all(p == (cx, cy) for p in first)
    # The last frame reaches beyond the farthest corner in every direction.
    far = max(((0 - cx) ** 2 + (0 - cy) ** 2) ** .5, ((0 - cx) ** 2 + (h - cy) ** 2) ** .5)
    assert min(((x - cx) ** 2 + (y - cy) ** 2) ** .5 for x, y in last) > far
