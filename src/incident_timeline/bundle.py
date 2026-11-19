"""Evidence bundle: one ZIP that anyone can check without ORISECT.

The bundle holds the evidence exactly as collected, the hash-chained custody
log, the case settings, the normalised timeline and the PDF report, plus:

  SHA256SUMS     standard `sha256sum -c` input covering every other file;
  manifest.json  what each evidence file is, its size and SHA-256 (taken from
                 the custody log, not from the editable case settings), the
                 custody chain's head and the verification result at export;
  README.txt     how to verify with sha256sum, PowerShell or ORISECT.

verify_bundle() repeats every check from the bundle alone: the SHA256SUMS
lines, each evidence file against its collect record, and every custody
record's hash and link to the one before.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from . import __version__
from .evidence import GENESIS_HASH, Case, _record_hash, now_utc, verify, verify_chain

README = """ORISECT evidence bundle for {case_id} ({case_name})
Exported {exported} by ORISECT {version}.

What is inside
  evidence/              the logs exactly as collected (byte for byte)
  custody.jsonl          the chain of custody; each record carries the SHA-256
                         of itself and of the record before it
  case.json              source settings (time zones, clock corrections, rules)
  normalised/            the normalised timeline and parsing gaps
  report.pdf             the investigation report
  manifest.json          each evidence file's size and SHA-256, and the custody
                         chain's head at export
  SHA256SUMS             a SHA-256 for every file above

Verify it
  Linux / macOS:   sha256sum -c SHA256SUMS
  Windows:         Get-FileHash -Algorithm SHA256 <file>, and compare with SHA256SUMS
  ORISECT:         incident-timeline verify-bundle <this zip or its folder>
                   (also re-checks every custody record's hash and link, and
                   each evidence file against the hash recorded at collection)

A matching hash shows a file is unchanged since export, and the custody chain
shows it is unchanged since collection. Neither proves what happened before
the logs were collected.
"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_bundle(case: Case, report_pdf: bytes | None = None) -> bytes:
    """The bundle as ZIP bytes. The verification at export is not written to the custody log."""
    meta = case.load_meta()
    custody = case.read_custody()
    result = verify(case, record=False)
    files: dict[str, bytes] = {}
    collected = {r["source_id"]: r for r in custody if r.get("action") == "collect"}
    entries = []
    for s in meta.get("sources", []):
        rec = collected.get(s["source_id"], {})
        rel = PurePosixPath(rec.get("evidence_path") or s["evidence_path"])
        path = case.root / rel
        if path.is_file():
            files[str(rel)] = path.read_bytes()
        entries.append({
            "source_id": s["source_id"], "original_name": s.get("original_name"), "path": str(rel),
            "source_type": s.get("source_type"), "host": s.get("host"),
            "size": rec.get("size", s.get("size")), "sha256": rec.get("sha256", s.get("sha256")),
            "collected_utc": rec.get("ts_utc"), "collected_by": rec.get("actor"),
            "time_zone": s.get("tz"), "clock_offset_s": s.get("skew_offset_s") or 0.0,
        })
    files["custody.jsonl"] = case.custody_file.read_bytes() if case.custody_file.exists() else b""
    files["case.json"] = case.case_file.read_bytes()
    for name in ("events.jsonl", "gaps.jsonl", "summary.json"):
        p = case.output_dir / name
        if p.is_file():
            files[f"normalised/{name}"] = p.read_bytes()
    if report_pdf:
        files["report.pdf"] = report_pdf
    head = custody[-1] if custody else {}
    manifest = {
        "format": "orisect-evidence-bundle/1", "algorithm": "SHA-256", "tool": f"ORISECT {__version__}",
        "exported_utc": now_utc(), "case_id": meta.get("case_id"), "case_name": meta.get("case_name"),
        "evidence": entries,
        "custody": {"records": len(custody), "head_seq": head.get("seq"), "head_sha256": head.get("record_sha256"),
                    "chain_ok": not result.chain_errors},
        "verification_at_export": {"ok": result.ok, "files_ok": result.files_ok,
                                   "problems": result.files_bad + result.chain_errors},
    }
    files["manifest.json"] = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode()
    files["README.txt"] = README.format(case_id=meta.get("case_id"), case_name=meta.get("case_name") or "untitled",
                                        exported=manifest["exported_utc"], version=__version__).encode()
    sums = "".join(f"{_sha(data)}  {name}\n" for name, data in sorted(files.items()))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for name, data in sorted(files.items()):
            zf.writestr(name, data)
        zf.writestr("SHA256SUMS", sums)
    return buf.getvalue()


def _read_bundle(path: Path) -> dict[str, bytes]:
    if path.is_dir():
        return {p.relative_to(path).as_posix(): p.read_bytes() for p in path.rglob("*") if p.is_file()}
    with zipfile.ZipFile(path) as zf:
        return {i.filename: zf.read(i) for i in zf.infolist() if not i.is_dir()}


def verify_bundle(path: Path | str) -> dict[str, Any]:
    """Check a bundle (ZIP or extracted folder) from its own contents. Returns {ok, checks, problems}."""
    files = _read_bundle(Path(path))
    problems: list[str] = []
    checks: list[str] = []
    sums = files.get("SHA256SUMS")
    if sums is None:
        return {"ok": False, "checks": [], "problems": ["SHA256SUMS is missing"]}
    listed = set()
    for line in sums.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        listed.add(name)
        if name not in files:
            problems.append(f"{name}: listed in SHA256SUMS but missing")
        elif _sha(files[name]) != digest:
            problems.append(f"{name}: SHA-256 does not match SHA256SUMS")
    extra = sorted(set(files) - listed - {"SHA256SUMS"})
    problems += [f"{name}: not covered by SHA256SUMS" for name in extra]
    checks.append(f"{len(listed)} files checked against SHA256SUMS")

    custody = [json.loads(ln) for ln in files.get("custody.jsonl", b"").decode("utf-8").splitlines() if ln.strip()]
    prev = GENESIS_HASH
    for i, rec in enumerate(custody, start=1):
        if rec.get("seq") != i or rec.get("prev_sha256") != prev or _record_hash(rec) != rec.get("record_sha256"):
            problems.append(f"custody record {i}: hash or link to the previous record is broken")
        prev = rec.get("record_sha256", "")
    checks.append(f"{len(custody)} custody records re-hashed and linked")

    for rec in (r for r in custody if r.get("action") == "collect"):
        data = files.get(rec.get("evidence_path", ""))
        if data is None:
            problems.append(f"{rec.get('source_id')}: evidence file missing ({rec.get('evidence_path')})")
        elif _sha(data) != rec.get("sha256") or len(data) != rec.get("size"):
            problems.append(f"{rec.get('source_id')}: evidence differs from the hash recorded at collection")
    checks.append(f"{sum(1 for r in custody if r.get('action') == 'collect')} evidence files matched to their collection hashes")

    try:
        manifest = json.loads(files.get("manifest.json", b"{}"))
        head = manifest.get("custody", {}).get("head_sha256")
        if custody and head and head != custody[-1].get("record_sha256"):
            problems.append("manifest.json: custody head does not match custody.jsonl")
    except json.JSONDecodeError:
        problems.append("manifest.json is not valid JSON")
    return {"ok": not problems, "checks": checks, "problems": problems}


def case_chain_ok(case: Case) -> bool:
    return not verify_chain(case)
