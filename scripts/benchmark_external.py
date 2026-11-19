"""Benchmark ORISECT on independently published logs: Elastic's NGINX sample.

Downloads the pinned file (or uses --source), checks its SHA-256, then for the
first 1,000 lines and for the whole file runs the web app's own upload path
in-process, three times each on fresh investigations, and measures:

  import   upload, evidence hashing and copying, parsing, findings and timeline build
  search   GET /api/events?q=GET&limit=50 (median of 5)
  pdf      GET /export/report.pdf
  bundle   GET /export/bundle.zip
  verify   evidence re-hash and custody-chain check

Usage:  python scripts/benchmark_external.py [--source nginx_logs] [--out results.json]
Processing time is machine time, not investigator time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from incident_timeline import __version__  # noqa: E402
from incident_timeline.evidence import Case, verify  # noqa: E402
from incident_timeline.web import TracefuseHandler  # noqa: E402

URL = ("https://raw.githubusercontent.com/elastic/examples/6d86454ebb7a850bcd7e80abe86fe683370018a6/"
       "Common%20Data%20Formats/nginx_logs/nginx_logs")
SHA256 = "526832433ab552466dc8623390fd92dc052b4f301b2eec94836a5c42a46937df"


def _multipart(name: str, data: bytes) -> tuple[bytes, str]:
    b = "----orisect-benchmark"
    body = (f'--{b}\r\nContent-Disposition: form-data; name="case_name"\r\n\r\nElastic NGINX sample\r\n'
            f'--{b}\r\nContent-Disposition: form-data; name="type_0"\r\n\r\nnginx\r\n'
            f'--{b}\r\nContent-Disposition: form-data; name="tz_0"\r\n\r\nUTC\r\n'
            f'--{b}\r\nContent-Disposition: form-data; name="file_0"; filename="{name}"\r\n\r\n').encode() \
        + data + f"\r\n--{b}--\r\n".encode()
    return body, f"multipart/form-data; boundary={b}"


def _timed(fn):
    t = time.perf_counter()
    out = fn()
    return out, time.perf_counter() - t


def run(data: bytes, label: str, root: Path, base: str, exports: bool = True) -> dict:
    body, ctype = _multipart(f"nginx_logs_{label}.log", data)
    req = urllib.request.Request(base + "/upload", data=body, headers={"Content-Type": ctype}, method="POST")
    resp, import_s = _timed(lambda: urllib.request.urlopen(req))
    case_id = resp.url.rsplit("/", 1)[-1].split("?")[0]
    resp.read()
    q = f"?case={case_id}"
    summary = json.load(urllib.request.urlopen(base + "/api/summary" + q))
    searches = []
    for _ in range(5):
        page, s = _timed(lambda: json.load(urllib.request.urlopen(base + "/api/events" + q + "&q=GET&limit=50")))
        searches.append(s)
    pdf_s = bundle_s = None
    bundle = b""
    if exports:  # the PDF lists every event, so it is measured on the 1,000-line set only
        _, pdf_s = _timed(lambda: urllib.request.urlopen(base + "/export/report.pdf" + q).read())
        bundle, bundle_s = _timed(lambda: urllib.request.urlopen(base + "/export/bundle.zip" + q).read())
    report, verify_s = _timed(lambda: verify(Case.open(root / case_id), record=False))
    records = data.count(b"\n")
    return {
        "input_records": records, "normalised": summary["events"], "gaps": summary["gaps"],
        "coverage_percent": round(100 * summary["events"] / records, 3),
        "import_seconds": import_s, "records_per_second": records / import_s,
        "search_ms_median": statistics.median(searches) * 1000, "search_matches": page["total"],
        "pdf_seconds": pdf_s, "bundle_seconds": bundle_s, "bundle_bytes": len(bundle),
        "verify_seconds": verify_s, "integrity_ok": report.ok,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", type=Path, help="local copy of the Elastic nginx_logs file (downloaded if omitted)")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    raw = args.source.read_bytes() if args.source else urllib.request.urlopen(URL).read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SHA256:
        print(f"source SHA-256 {digest} does not match the pinned file {SHA256}", file=sys.stderr)
        return 1
    lines = raw.splitlines(keepends=True)
    sets = {"prefix_1000": b"".join(lines[:1000]), "full": raw}

    results = {"dataset": "Elastic examples / NGINX combined sample logs", "source_url": URL, "source_sha256": SHA256,
               "source_bytes": len(raw), "source_records": len(lines), "tool": f"ORISECT {__version__}",
               "measured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "runtime": {"python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine(),
                           "processor": platform.processor() or "unknown"},
               "sets": {}}
    with tempfile.TemporaryDirectory(prefix="orisect-bench-") as tmp:
        root = Path(tmp)
        handler = type("BenchHandler", (TracefuseHandler,), {"case_root": root, "cases_root": root, "app_mode": True,
                                                             "log_message": lambda *a: None})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            for name, data in sets.items():
                runs = [run(data, name, root, base, exports=name != "full") for _ in range(args.runs)]
                med = {k: statistics.median(r[k] for r in runs) for k in runs[0]
                       if isinstance(runs[0][k], (int, float)) and not isinstance(runs[0][k], bool)}
                results["sets"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "runs": runs, "median": med}
                extra = (f"  pdf {med['pdf_seconds']:.2f}s  bundle {med['bundle_seconds']:.2f}s" if "pdf_seconds" in med else "")
                print(f"{name:12} {med['input_records']:>7,.0f} records  normalised {med['normalised']:>7,.0f}  "
                      f"gaps {med['gaps']:>4,.0f}  import {med['import_seconds']:.3f}s  "
                      f"{med['records_per_second']:>9,.0f} rec/s  search {med['search_ms_median']:.1f} ms{extra}  "
                      f"verify {med['verify_seconds'] * 1000:.1f} ms  integrity {all(r['integrity_ok'] for r in runs)}", flush=True)
        finally:
            server.shutdown()
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
