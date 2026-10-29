"""Evidence collection, chain of custody and re-verification.

Follows NIST SP 800-86 and RFC 3227: originals are never parsed. Each log
is copied into the case's evidence store, hashed with SHA-256 (FIPS 180-4)
while copying, re-hashed after copying, and made read-only. Every action
is appended to custody.jsonl, where each record also carries the hash of
the record before it, so any later edit to the custody log is detectable.

Case directory layout:

    CASE/
      case.json          case metadata and per-source settings
      custody.jsonl      hash-chained custody records
      evidence/          read-only copies, e.g. S001_auth.log
      normalised/        outputs of the parse stage
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import socket
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .timeutil import UTC, resolve_tz, to_rfc3339

GENESIS_HASH = "0" * 64
CHUNK = 1 << 20

SOURCE_TYPES = {
    "syslog": "syslog",
    "auth": "syslog",
    "access": "access",
    "apache": "access",
    "nginx": "access",
    "other": "custom",  # no built-in parser; lines stay unparsed until a parser rule covers them
    "custom": "custom",
}


class EvidenceError(Exception):
    pass


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def default_actor() -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    return f"{user}@{socket.gethostname()}"


def now_utc() -> str:
    return to_rfc3339(datetime.now(UTC))


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _record_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "record_sha256"}
    return hashlib.sha256(_canonical(body)).hexdigest()


@dataclass
class Case:
    root: Path

    @property
    def case_file(self) -> Path:
        return self.root / "case.json"

    @property
    def custody_file(self) -> Path:
        return self.root / "custody.jsonl"

    @property
    def evidence_dir(self) -> Path:
        return self.root / "evidence"

    @property
    def output_dir(self) -> Path:
        return self.root / "normalised"

    @classmethod
    def open(cls, root: Path | str, create: bool = False) -> "Case":
        case = cls(Path(root))
        if not case.case_file.exists():
            if not create:
                raise EvidenceError(f"no case at {case.root} (case.json missing)")
            case.root.mkdir(parents=True, exist_ok=True)
            case.evidence_dir.mkdir(exist_ok=True)
            case.save_meta({
                "case_id": case.root.name,
                "created_utc": now_utc(),
                "tool_version": __version__,
                "sources": [],
            })
        return case

    def load_meta(self) -> dict[str, Any]:
        with open(self.case_file, encoding="utf-8") as fh:
            return json.load(fh)

    def save_meta(self, meta: dict[str, Any]) -> None:
        tmp = self.case_file.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(meta, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, self.case_file)

    def sources(self) -> list[dict[str, Any]]:
        return self.load_meta()["sources"]

    def source(self, source_id: str) -> dict[str, Any]:
        for s in self.sources():
            if s["source_id"] == source_id:
                return s
        raise EvidenceError(f"unknown source {source_id!r}")

    def update_source(self, source_id: str, **changes: Any) -> None:
        meta = self.load_meta()
        for s in meta["sources"]:
            if s["source_id"] == source_id:
                s.update(changes)
                self.save_meta(meta)
                return
        raise EvidenceError(f"unknown source {source_id!r}")

    def read_custody(self) -> list[dict[str, Any]]:
        if not self.custody_file.exists():
            return []
        with open(self.custody_file, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def append_custody(self, action: str, actor: str | None = None, **fields: Any) -> dict[str, Any]:
        records = self.read_custody()
        record: dict[str, Any] = {
            "seq": len(records) + 1,
            "ts_utc": now_utc(),
            "action": action,
            "actor": actor or default_actor(),
            "tool": f"incident_timeline {__version__}",
            **fields,
            "prev_sha256": records[-1]["record_sha256"] if records else GENESIS_HASH,
        }
        record["record_sha256"] = _record_hash(record)
        with open(self.custody_file, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name) or "log"


def collect(
    case: Case,
    original: Path | str,
    source_type: str,
    tz: str | None = None,
    host: str | None = None,
    year: int | None = None,
    actor: str | None = None,
    note: str = "",
    allow_duplicate: bool = False,
) -> dict[str, Any]:
    """Copy one log into the evidence store and record custody.

    tz is the zone the source host writes local times in. It matters for
    formats without an offset (classic syslog); when omitted, UTC is
    assumed and every event is flagged tz_assumed.
    """
    original = Path(original)
    if not original.is_file():
        raise EvidenceError(f"not a file: {original}")
    stype = SOURCE_TYPES.get(source_type.lower())
    if stype is None:
        raise EvidenceError(f"unknown source type {source_type!r}; use one of {sorted(SOURCE_TYPES)}")
    if tz is not None:
        resolve_tz(tz)  # fail early on a bad zone

    meta = case.load_meta()
    source_id = f"S{len(meta['sources']) + 1:03d}"
    case.evidence_dir.mkdir(exist_ok=True)
    dest = case.evidence_dir / f"{source_id}_{_safe_name(original.name)}"
    if dest.exists():
        raise EvidenceError(f"evidence file already exists: {dest}")

    st = original.stat()
    h = hashlib.sha256()
    size = 0
    tmp = dest.with_name(dest.name + ".partial")
    with open(original, "rb") as src, open(tmp, "xb") as out:
        while chunk := src.read(CHUNK):
            h.update(chunk)
            out.write(chunk)
            size += len(chunk)
    digest = h.hexdigest()

    if not allow_duplicate:
        dup = next((s for s in meta["sources"] if s["sha256"] == digest), None)
        if dup:
            tmp.unlink()
            raise EvidenceError(f"identical content already collected as {dup['source_id']}")

    os.replace(tmp, dest)
    os.utime(dest, (st.st_atime, st.st_mtime))
    os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    copy_digest, copy_size = sha256_file(dest)
    if copy_digest != digest or copy_size != size:
        raise EvidenceError(f"copy of {original} does not match the original's hash")

    rel = dest.relative_to(case.root).as_posix()
    mtime = to_rfc3339(datetime.fromtimestamp(st.st_mtime, UTC))
    source = {
        "source_id": source_id,
        "source_type": stype,
        "original_path": str(original.resolve()),
        "original_name": original.name,
        "evidence_path": rel,
        "sha256": digest,
        "size": size,
        "original_mtime_utc": mtime,
        "tz": tz or "UTC",
        "tz_assumed": tz is None,
        "host": host,
        "year": year,
        "skew_offset_s": 0.0,
        "skew_method": None,
    }
    meta["sources"].append(source)
    case.save_meta(meta)
    case.append_custody(
        "collect",
        actor,
        source_id=source_id,
        original_path=source["original_path"],
        evidence_path=rel,
        sha256=digest,
        size=size,
        original_mtime_utc=mtime,
        note=note,
    )
    return source


@dataclass
class VerifyReport:
    files_ok: list[str] = field(default_factory=list)
    files_bad: list[str] = field(default_factory=list)
    chain_errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.files_bad and not self.chain_errors


def verify_chain(case: Case) -> list[str]:
    """Check every custody record's hash and its link to the previous one."""
    errors = []
    prev = GENESIS_HASH
    for i, rec in enumerate(case.read_custody(), start=1):
        if rec.get("seq") != i:
            errors.append(f"record {i}: sequence number is {rec.get('seq')}")
        if rec.get("prev_sha256") != prev:
            errors.append(f"record {i}: link to previous record is broken")
        if _record_hash(rec) != rec.get("record_sha256"):
            errors.append(f"record {i}: contents do not match its hash")
        prev = rec.get("record_sha256", "")
    return errors


def check_source(case: Case, source_id: str) -> str | None:
    """Re-hash one evidence copy; return None if it matches, else the problem.

    The expected hash comes from the custody log, not case.json, because
    case.json holds editable settings while the custody log is hash-chained.
    """
    rec = next((r for r in case.read_custody()
                if r["action"] == "collect" and r.get("source_id") == source_id), None)
    if rec is None:
        return f"{source_id}: no collect record in the custody log"
    path = case.root / rec["evidence_path"]
    if not path.is_file():
        return f"{source_id}: evidence file missing ({rec['evidence_path']})"
    digest, size = sha256_file(path)
    if digest != rec["sha256"] or size != rec["size"]:
        return f"{source_id}: hash mismatch ({rec['evidence_path']}); evidence has changed"
    return None


def verify(case: Case, actor: str | None = None, record: bool = True) -> VerifyReport:
    """Re-hash every evidence copy and check the custody chain."""
    report = VerifyReport(chain_errors=verify_chain(case))
    for s in case.sources():
        problem = check_source(case, s["source_id"])
        if problem:
            report.files_bad.append(problem)
        else:
            report.files_ok.append(s["source_id"])
    if record:
        case.append_custody(
            "verify",
            actor,
            result="pass" if report.ok else "fail",
            files_ok=report.files_ok,
            problems=report.files_bad + report.chain_errors,
        )
    return report
