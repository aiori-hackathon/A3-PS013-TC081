"""Command-line interface: python -m incident_timeline <command> ...

    collect  copy a log into a case as hashed, read-only evidence
    sources  list a case's sources and their settings
    verify   re-hash all evidence and check the custody chain
    skew     estimate, anchor or set clock-skew offsets
    parse    build the normalised UTC timeline
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Sequence

from . import __version__
from .evidence import SOURCE_TYPES, Case, EvidenceError, collect, verify
from .pipeline import anchor_skew, apply_skew, build_timeline, estimate_case_skew
from .skew import SkewEstimate
from .scenarios import create_demo_cases
from .web import serve_app, serve_case


def _cmd_collect(args: argparse.Namespace) -> int:
    case = Case.open(args.case, create=True)
    s = collect(case, args.file, args.type, tz=args.tz, host=args.host, year=args.year,
                actor=args.actor, note=args.note or "", allow_duplicate=args.allow_duplicate)
    print(f"{s['source_id']}  {s['original_name']}  sha256={s['sha256']}  {s['size']} bytes")
    print(f"  stored read-only at {case.root / s['evidence_path']}")
    if s["tz_assumed"] and s["source_type"] == "syslog":
        print("  warning: no --tz given; times without a UTC offset will be treated as UTC")
    return 0


def _cmd_sources(args: argparse.Namespace) -> int:
    case = Case.open(args.case)
    for s in case.sources():
        tz = s["tz"] + (" (assumed)" if s.get("tz_assumed") else "")
        print(f"{s['source_id']}  {s['source_type']:<7} {s['original_name']:<24} tz={tz:<20} "
              f"host={s.get('host') or '-':<10} skew={s.get('skew_offset_s') or 0:+g}s  "
              f"sha256={s['sha256'][:16]}...")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    case = Case.open(args.case)
    report = verify(case, actor=args.actor)
    for sid in report.files_ok:
        print(f"OK    {sid}")
    for problem in report.files_bad + report.chain_errors:
        print(f"FAIL  {problem}")
    print("verification passed" if report.ok else "verification FAILED")
    return 0 if report.ok else 1


def _print_estimate(e: SkewEstimate) -> None:
    if e.offset_s is None:
        print(f"{e.source_id} vs {e.reference_id}: no reliable offset "
              f"({e.matches} matching pairs in best cluster, {e.candidate_pairs} candidates)")
    else:
        print(f"{e.source_id} vs {e.reference_id}: clock {e.offset_s:+.3f}s "
              f"({'ahead' if e.offset_s >= 0 else 'behind'}), {e.matches} matches of "
              f"{e.candidate_pairs} candidates, spread {e.spread_s:g}s  [{e.method}]")


_LINE_REF = re.compile(r"^(S\d+):(\d+)$")


def _line_ref(text: str) -> tuple[str, int]:
    m = _LINE_REF.match(text.strip())
    if not m:
        raise EvidenceError(f"expected SOURCE:LINE such as S002:120, got {text!r}")
    return m.group(1), int(m.group(2))


def _cmd_skew(args: argparse.Namespace) -> int:
    case = Case.open(args.case)
    if args.set:
        sid, _, value = args.set.partition("=")
        est = SkewEstimate(sid.strip(), "-", float(value), 0, 0, None, "manual")
        case.source(est.source_id)
        apply_skew(case, est, args.actor)
        print(f"{est.source_id}: offset set to {est.offset_s:+g}s (manual)")
        return 0

    if args.anchor:
        left, _, right = args.anchor.partition("=")
        estimates = [anchor_skew(case, _line_ref(left), _line_ref(right))]
    else:
        if not args.reference:
            raise EvidenceError("give --reference SOURCE, --anchor S002:LINE=S001:LINE or --set S002=SECONDS")
        estimates = estimate_case_skew(
            case, args.reference, [f.strip() for f in args.match_on.split(",")],
            args.window, args.tolerance, args.min_matches,
        )
    for e in estimates:
        _print_estimate(e)
        if args.apply and e.usable:
            apply_skew(case, e, args.actor)
            print(f"  applied to {e.source_id}")
    if not args.apply:
        print("(dry run; add --apply to store usable offsets)")
    return 0


def _cmd_parse(args: argparse.Namespace) -> int:
    case = Case.open(args.case)
    out = build_timeline(case, actor=args.actor, force=args.force)
    s = out.summary
    print(f"{s['events']} events, {s['gaps']} unparsed lines -> {case.output_dir}")
    for src in s["sources"]:
        ratio = f"{src['parsed_ratio']:.1%}" if src["parsed_ratio"] is not None else "n/a"
        print(f"  {src['source_id']} {src['source_file']}: {src['events']} events, "
              f"{src['gaps']} gaps ({ratio} parsed), skew {src['skew_offset_s']:+g}s")
        if src["tz_assumed_events"]:
            print(f"    warning: {src['tz_assumed_events']} events had no zone; UTC was assumed (set --tz on collect)")
        for note in src["notes"]:
            print(f"    note: {note}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    serve_case(args.case, host=args.host, port=args.port)
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    results = create_demo_cases(args.output)
    for result in results:
        state = "PASS" if result["passed"] else "FAIL"
        print(f"{state:<4} {result['scenario_id']}: {result['event_count']} events, {result['gap_count']} gaps")
        print(f"     case: {result['case_path']}")
    passed = sum(bool(result["passed"]) for result in results)
    print(f"{passed}/{len(results)} synthetic scenarios passed; manifest: {args.output}/manifest.json")
    return 0 if passed == len(results) else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="incident-timeline", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--actor", help="who is performing this action (default: user@host)")

    c = sub.add_parser("collect", parents=[common], help="copy a log into the case as evidence")
    c.add_argument("case", help="case directory (created if missing)")
    c.add_argument("file", help="log file to collect (.gz accepted)")
    c.add_argument("--type", required=True, choices=sorted(SOURCE_TYPES), help="log format")
    c.add_argument("--tz", help="zone the host logs in, e.g. Asia/Kolkata or +05:30 (default: UTC, flagged)")
    c.add_argument("--host", help="host name, for logs that do not record one")
    c.add_argument("--year", type=int, help="year of the first line, for logs without a year")
    c.add_argument("--note", help="free-text custody note")
    c.add_argument("--allow-duplicate", action="store_true", help="collect even if identical content exists")
    c.set_defaults(func=_cmd_collect)

    s = sub.add_parser("sources", parents=[common], help="list sources in a case")
    s.add_argument("case")
    s.set_defaults(func=_cmd_sources)

    v = sub.add_parser("verify", parents=[common], help="re-hash evidence and check custody chain")
    v.add_argument("case")
    v.set_defaults(func=_cmd_verify)

    k = sub.add_parser("skew", parents=[common], help="estimate or set clock-skew offsets")
    k.add_argument("case")
    k.add_argument("--reference", help="source whose clock is trusted, e.g. S001")
    k.add_argument("--match-on", default="src_ip", help="comma-separated event fields to pair on (default: src_ip)")
    k.add_argument("--window", type=float, default=3600.0, help="largest skew to search for, seconds")
    k.add_argument("--tolerance", type=float, default=2.0, help="how tightly matches must agree, seconds")
    k.add_argument("--min-matches", type=int, default=3)
    k.add_argument("--anchor", help="SOURCE:LINE=REF:LINE, two lines recording the same event")
    k.add_argument("--set", help="SOURCE=SECONDS, set an offset by hand")
    k.add_argument("--apply", action="store_true", help="store the offsets in the case")
    k.set_defaults(func=_cmd_skew)

    r = sub.add_parser("parse", parents=[common], help="build the normalised timeline")
    r.add_argument("case")
    r.add_argument("--force", action="store_true", help="parse even if evidence fails verification")
    r.set_defaults(func=_cmd_parse)

    w = sub.add_parser("serve", parents=[common], help="open a local web dashboard for a parsed case")
    w.add_argument("case", help="case directory with normalised/events.jsonl")
    w.add_argument("--host", default="127.0.0.1", help="interface to bind (default: localhost only)")
    w.add_argument("--port", type=int, default=8765, help="local dashboard port (default: 8765)")
    w.set_defaults(func=_cmd_serve)

    a = sub.add_parser("app", help="launch the TRACEFUSE web application with upload and demo workflows")
    a.add_argument("--host", default="127.0.0.1", help="interface to bind (default: localhost only)")
    a.add_argument("--port", type=int, default=8765, help="port to serve the web app on")
    a.add_argument("--cases-dir", default="cases/web-app", help="directory for uploaded investigations")
    a.set_defaults(func=lambda args: serve_app(host=args.host, port=args.port, cases_dir=args.cases_dir) or 0)

    d = sub.add_parser("demo", help="generate and validate three synthetic incident scenarios")
    d.add_argument("--output", default="cases/demo-scenarios", help="output directory (default: cases/demo-scenarios)")
    d.set_defaults(func=_cmd_demo)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (EvidenceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
