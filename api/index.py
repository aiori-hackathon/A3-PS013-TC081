"""Vercel entry point: serves the ORISECT web app as a Python serverless function.

Vercel's Python runtime calls the ``handler`` class (a BaseHTTPRequestHandler) for
every request. vercel.json rewrites every URL to this function and passes the
original path in ``__path``, which is restored before the app routes the request.
Uploaded cases live in /tmp, the only writable directory on Vercel, so they last
only as long as the function instance that holds them.
"""

import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from incident_timeline.web import TracefuseHandler  # noqa: E402

CASES_ROOT = Path("/tmp/orisect-cases")
CASES_ROOT.mkdir(parents=True, exist_ok=True)


def original_path(path: str) -> str:
    """Undo Vercel's rewrite: /api/index?__path=/x&a=1 -> /x?a=1."""
    url = urlsplit(path)
    query = parse_qsl(url.query, keep_blank_values=True)
    target = next((v for k, v in query if k == "__path"), None)
    if target is None:
        return path
    rest = urlencode([(k, v) for k, v in query if k != "__path"])
    target = "/" + target.lstrip("/")
    return f"{target}?{rest}" if rest else target


class handler(TracefuseHandler):  # noqa: N801 - name required by Vercel
    case_root = CASES_ROOT
    cases_root = CASES_ROOT
    app_mode = True

    def parse_request(self) -> bool:
        ok = super().parse_request()
        if ok:
            self.path = original_path(self.path)
        return ok
