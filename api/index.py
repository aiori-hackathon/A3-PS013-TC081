"""Vercel entry point: serves the ORISECT web app as a Python serverless function.

Vercel's Python runtime calls the ``handler`` class (a BaseHTTPRequestHandler) for
every request. vercel.json rewrites every URL to this function and passes the
original path in ``__path``, which is restored before the app routes the request.

Hosting adds three limits the local app doesn't need:
- Uploaded cases live in /tmp, the only writable directory on Vercel. Cases older
  than CASE_TTL_S are deleted and at most MAX_CASES are kept, so anonymous uploads
  can't fill the disk.
- Each client IP may make UPLOADS_PER_WINDOW uploads per UPLOAD_WINDOW_S.
- Vercel rejects request bodies over 4.5 MB, so the upload page advertises 4 MB
  instead of the local 25 MB.
"""

import shutil
import sys
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from incident_timeline.web import TracefuseHandler  # noqa: E402

CASES_ROOT = Path("/tmp/orisect-cases")
CASES_ROOT.mkdir(parents=True, exist_ok=True)

CASE_TTL_S = 6 * 60 * 60
MAX_CASES = 40
UPLOADS_PER_WINDOW = 10
UPLOAD_WINDOW_S = 10 * 60
MAX_UPLOAD_BYTES = 4 * 1024 * 1024

_uploads: dict[str, deque] = defaultdict(deque)
_lock = threading.Lock()


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


def prune_cases(root: Path = CASES_ROOT, now: float | None = None) -> None:
    """Delete expired cases, then the oldest beyond MAX_CASES - 1 to make room for a new one."""
    now = time.time() if now is None else now
    cases = sorted((p for p in root.glob("CASE-*") if p.is_dir()), key=lambda p: p.stat().st_mtime)
    keep = []
    for case in cases:
        if now - case.stat().st_mtime > CASE_TTL_S:
            shutil.rmtree(case, ignore_errors=True)
        else:
            keep.append(case)
    for case in keep[: max(0, len(keep) - (MAX_CASES - 1))]:
        shutil.rmtree(case, ignore_errors=True)


def allow_upload(client: str, now: float | None = None) -> bool:
    """Sliding-window limit on uploads per client IP (per function instance)."""
    now = time.monotonic() if now is None else now
    with _lock:
        recent = _uploads[client]
        while recent and now - recent[0] > UPLOAD_WINDOW_S:
            recent.popleft()
        if len(recent) >= UPLOADS_PER_WINDOW:
            return False
        recent.append(now)
        return True


class handler(TracefuseHandler):  # noqa: N801 - name required by Vercel
    case_root = CASES_ROOT
    cases_root = CASES_ROOT
    app_mode = True

    def parse_request(self) -> bool:
        ok = super().parse_request()
        if ok:
            self.path = original_path(self.path)
        return ok

    def _client(self) -> str:
        forwarded = self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For", "")
        return forwarded.split(",")[0].strip() or self.client_address[0]

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        if urlsplit(self.path).path == "/upload" and not self._cross_site():
            if int(self.headers.get("Content-Length") or 0) > MAX_UPLOAD_BYTES:
                self._fail(413, "Uploads to the hosted demo must be 4 MB or less in total.")
                return
            if not allow_upload(self._client()):
                self._fail(429, "Too many uploads from your address. Try again in a few minutes.")
                return
            prune_cases()
        super().do_POST()

    def _send(self, status, body, content_type="application/json; charset=utf-8", *args, **kwargs):
        if content_type.startswith("text/html") and urlsplit(self.path).path in ("/", "/index.html"):
            body = body.replace(b"25 * 1024 * 1024", b"4 * 1024 * 1024").replace(b"25 MB", b"4 MB")
        super()._send(status, body, content_type, *args, **kwargs)
