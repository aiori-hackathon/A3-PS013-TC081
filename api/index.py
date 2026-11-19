"""Vercel entry point: serves the ORISECT web app as a Python serverless function.

Vercel's Python runtime calls the ``handler`` class (a BaseHTTPRequestHandler) for
every request. vercel.json rewrites every URL to this function and passes the
original path in ``__path``, which is restored before the app routes the request.

Hosting adds what the local app doesn't need:

Persistence. Each serverless instance has its own short-lived /tmp, so a case
uploaded to one instance can be missing, or older, on the instance that answers
the next request. After every change (upload, rule approval or revocation) the
server hands the browser a signed tar.gz of the case; casestore.js keeps it in
IndexedDB. Each request says which version the browser holds (X-Orisect-Expect).
An instance without the case answers 404 and one with an older custody chain
answers 409; the browser then POSTs the archive to /api/case-restore and retries.
The signature (HMAC over case id, version and archive hash, keyed by the
ORISECT_SECRET environment variable) stops anyone planting a forged case.

Limits. Cases expire after CASE_TTL_S and at most MAX_CASES are kept per
instance; each client IP gets UPLOADS_PER_WINDOW uploads per UPLOAD_WINDOW_S;
uploads are capped at 4 MB (Vercel rejects bodies over 4.5 MB).

Privacy. /api/cases lists nothing, so one visitor can't enumerate another's cases.
"""

import base64
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import threading
import time
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from incident_timeline.web import TracefuseHandler  # noqa: E402

CASES_ROOT = Path("/tmp/orisect-cases")
CASES_ROOT.mkdir(parents=True, exist_ok=True)

CASE_TTL_S = 6 * 60 * 60
MAX_CASES = 40
UPLOADS_PER_WINDOW = 10
UPLOAD_WINDOW_S = 10 * 60
MAX_UPLOAD_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 4_400_000          # under Vercel's 4.5 MB request limit
MAX_EXTRACTED_BYTES = 96 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000

CASE_ID = re.compile(r"CASE-[a-f0-9]{12}")
_SECRET = (os.environ.get("ORISECT_SECRET") or "").encode()
if not _SECRET:
    print("ORISECT: ORISECT_SECRET is not set; case archives are signed with a fallback key.", file=sys.stderr)
    _SECRET = hashlib.sha256(b"orisect-fallback:" + os.environ.get("VERCEL_PROJECT_ID", "").encode()).digest()

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


def prune_cases(root: Path = CASES_ROOT, now: float | None = None, keep: str | None = None) -> None:
    """Delete expired cases, then the oldest beyond MAX_CASES - 1 to make room for a new one."""
    now = time.time() if now is None else now
    cases = sorted((p for p in root.glob("CASE-*") if p.is_dir() and p.name != keep), key=lambda p: p.stat().st_mtime)
    alive = []
    for case in cases:
        if now - case.stat().st_mtime > CASE_TTL_S:
            shutil.rmtree(case, ignore_errors=True)
        else:
            alive.append(case)
    for case in alive[: max(0, len(alive) - (MAX_CASES - 1))]:
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


# ---------- Case versions, archives and signatures ----------

def case_version(case_dir: Path) -> str:
    """'<custody seq>:<head record hash>'. Every change to a case appends a custody record."""
    custody = case_dir / "custody.jsonl"
    try:
        lines = [ln for ln in custody.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError:
        return "0:"
    if not lines:
        return "0:"
    head = json.loads(lines[-1])
    return f"{int(head.get('seq', len(lines)))}:{head.get('record_sha256', '')}"


def version_seq(version: str | None) -> int:
    try:
        return int(str(version or "0").split(":", 1)[0])
    except ValueError:
        return 0


def sign(case_id: str, version: str, data: bytes) -> str:
    msg = f"{case_id}\n{version}\n{hashlib.sha256(data).hexdigest()}".encode()
    return hmac.new(_SECRET, msg, hashlib.sha256).hexdigest()


def make_archive(case_dir: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        for path in sorted(case_dir.rglob("*")):
            if path.is_file() and not path.name.endswith(".partial"):
                tar.add(path, arcname=path.relative_to(case_dir).as_posix(), recursive=False)
    return buf.getvalue()


def extract_archive(data: bytes, dest: Path) -> None:
    """Unpack a case archive, refusing anything but plain files and folders inside dest."""
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive has too many entries")
        for m in members:
            name = PurePosixPath(m.name)
            if name.is_absolute() or ".." in name.parts or not (m.isfile() or m.isdir()):
                raise ValueError(f"unsafe archive entry: {m.name!r}")
            total += m.size
            if total > MAX_EXTRACTED_BYTES:
                raise ValueError("archive expands beyond the size limit")
        if sys.version_info >= (3, 12):
            tar.extractall(dest, filter="data")
        else:  # members were validated above
            tar.extractall(dest)  # noqa: S202


class handler(TracefuseHandler):  # noqa: N801 - name required by Vercel
    case_root = CASES_ROOT
    cases_root = CASES_ROOT
    app_mode = True

    def parse_request(self) -> bool:
        ok = super().parse_request()
        if ok:
            self.path = original_path(self.path)
            self._extra_headers: list[tuple[str, str]] = []
        return ok

    # ---------- helpers ----------
    def _client(self) -> str:
        forwarded = self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For", "")
        return forwarded.split(",")[0].strip() or self.client_address[0]

    def _case_id(self) -> str | None:
        url = urlsplit(self.path)
        candidate = (parse_qs(url.query).get("case") or [""])[0]
        if not CASE_ID.fullmatch(candidate):
            m = re.match(r"^/case/(CASE-[a-f0-9]{12})/?$", url.path)
            candidate = m.group(1) if m else ""
        return candidate or None

    def _case_dir(self, case_id: str) -> Path | None:
        d = CASES_ROOT / case_id
        return d if (d / "case.json").is_file() else None

    def _signed_archive(self, case_dir: Path) -> tuple[bytes, str, str]:
        data = make_archive(case_dir)
        version = case_version(case_dir)
        return data, version, sign(case_dir.name, version, data)

    def end_headers(self) -> None:
        for name, value in getattr(self, "_extra_headers", []):
            self.send_header(name, value)
        self._extra_headers = []
        super().end_headers()

    def _stale(self) -> bool:
        """Refuse a request when this instance lacks the case (404) or holds an older copy (409)."""
        case_id = self._case_id()
        if not case_id:
            return False
        case_dir = self._case_dir(case_id)
        if case_dir is None:
            if urlsplit(self.path).path.startswith(("/api/", "/export/")):
                self._fail(404, "Investigation not found")  # the browser restores it and retries
                return True
            return False
        expected = self.headers.get("X-Orisect-Expect")
        if not expected:
            return False
        local = case_version(case_dir)
        if local == expected or version_seq(local) > version_seq(expected):
            return False
        self._fail(409, "This server copy of the investigation is out of date.")
        return True

    def _fail(self, status: int, message: str) -> None:
        body = {"error": message}
        if status == 409 and "out of date" in message:
            body["stale"] = True
        self._send(status, json.dumps(body).encode(), "application/json; charset=utf-8")

    # ---------- responses ----------
    def _send(self, status, body, content_type="application/json; charset=utf-8", *args, **kwargs):
        if content_type.startswith("text/html") and urlsplit(self.path).path in ("/", "/index.html"):
            body = body.replace(b"25 * 1024 * 1024", b"4 * 1024 * 1024").replace(b"25 MB", b"4 MB")
        case_id = self._case_id()
        case_dir = self._case_dir(case_id) if case_id else None
        if case_dir is not None:
            self._extra_headers.append(("X-Orisect-Version", case_version(case_dir)))
            # A change through the rules API returns the updated, signed archive with its JSON.
            if (self.command == "POST" and urlsplit(self.path).path.startswith("/api/rules/") and status == 200
                    and self.headers.get("X-Orisect-Archive") == "1" and content_type.startswith("application/json")):
                data, version, signature = self._signed_archive(case_dir)
                if len(data) <= MAX_ARCHIVE_BYTES:
                    payload = json.loads(body)
                    payload.update(_archive=base64.b64encode(data).decode("ascii"), _version=version, _signature=signature)
                    body = json.dumps(payload).encode()
        super()._send(status, body, content_type, *args, **kwargs)

    def _upload_complete(self, case_id: str, skipped: list[str]) -> None:
        location = f"/case/{case_id}" + (f"?dupes={len(skipped)}" if skipped else "")
        case_dir = self._case_dir(case_id)
        if self.headers.get("X-Orisect-Archive") != "1" or case_dir is None:
            super()._upload_complete(case_id, skipped)
            return
        data, version, signature = self._signed_archive(case_dir)
        self._extra_headers += [("X-Orisect-Location", location), ("X-Orisect-Case", case_id),
                                ("X-Orisect-Version", version), ("X-Orisect-Signature", signature)]
        self._send(200, data, "application/gzip")

    # ---------- routes ----------
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        path = urlsplit(self.path).path
        if path == "/api/cases":
            self._send(200, b'{"cases": []}')
            return
        if path == "/api/case-archive":
            case_id = self._case_id()
            case_dir = self._case_dir(case_id) if case_id else None
            if case_dir is None:
                self._fail(404, "Investigation not found")
                return
            data, _version, signature = self._signed_archive(case_dir)
            self._extra_headers.append(("X-Orisect-Signature", signature))
            self._send(200, data, "application/gzip")
            return
        m = re.match(r"^/case/(CASE-[a-f0-9]{12})/?$", path)
        if m and self._case_dir(m.group(1)) is None:
            # The page loads anyway; its first API call restores the case from the browser.
            self._send(200, self._case_page(m.group(1)), "text/html; charset=utf-8")
            return
        if self._stale():
            return
        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        path = urlsplit(self.path).path
        if self._cross_site():
            self._fail(403, "Cross-site request refused")
            return
        if path == "/api/case-restore":
            self._restore()
            return
        if path == "/upload":
            if int(self.headers.get("Content-Length") or 0) > MAX_UPLOAD_BYTES:
                self._fail(413, "Uploads to the hosted demo must be 4 MB or less in total.")
                return
            if not allow_upload(self._client()):
                self._fail(429, "Too many uploads from your address. Try again in a few minutes.")
                return
            prune_cases()
        elif self._stale():
            return
        super().do_POST()

    def _restore(self) -> None:
        case_id = self._case_id()
        version = self.headers.get("X-Orisect-Version", "")
        signature = self.headers.get("X-Orisect-Signature", "")
        length = int(self.headers.get("Content-Length") or 0)
        if not case_id or not version or not signature:
            self._fail(400, "Missing case, version or signature.")
            return
        if length <= 0 or length > MAX_ARCHIVE_BYTES:
            self._fail(413, "Case archive is too large to restore.")
            return
        data = self.rfile.read(length)
        if not hmac.compare_digest(sign(case_id, version, data), signature):
            self._fail(403, "Case archive signature does not match.")
            return
        with _lock:
            current = self._case_dir(case_id)
            if current is not None and (case_version(current) == version or version_seq(case_version(current)) > version_seq(version)):
                self._send(200, json.dumps({"restored": False, "version": case_version(current)}).encode())
                return
            staging = Path(tempfile.mkdtemp(prefix=".restore-", dir=CASES_ROOT))
            try:
                extract_archive(data, staging)
                if not (staging / "case.json").is_file() or case_version(staging) != version:
                    raise ValueError("archive does not match its version")
                prune_cases(keep=case_id)
                target = CASES_ROOT / case_id
                if target.exists():
                    old = target.with_name(f".old-{case_id}-{time.time_ns()}")
                    target.rename(old)
                    shutil.rmtree(old, ignore_errors=True)
                staging.rename(target)
            except (ValueError, tarfile.TarError, OSError, json.JSONDecodeError) as exc:
                shutil.rmtree(staging, ignore_errors=True)
                self._fail(400, f"Case archive could not be restored: {exc}")
                return
        self._send(200, json.dumps({"restored": True, "version": version}).encode())
