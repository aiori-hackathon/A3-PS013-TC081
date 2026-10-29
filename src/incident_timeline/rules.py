"""Analyst-approved parser rules for log formats ORISECT has no parser for.

A line no built-in parser understood is kept as a gap. The rule assistant
looks at a source's gap lines, proposes a rule (how to find the timestamp
and which parts become which fields), and the analyst tests and approves
it. An approved rule is plain data: a regular expression or key=value
extraction plus a field mapping, applied deterministically on every parse.

Approval is evidence handling, so rules live in the hash-chained custody
log, not in case.json. Each approve_parser_rule record carries the full
rule definition and its SHA-256; a revoke_parser_rule record withdraws it.
The pipeline reads the active rules from custody only, so a rule cannot be
changed without leaving a trace.

Rule definition (JSON):

    {
      "name": "fw01 traffic log",
      "source_ids": ["S003"],
      "mode": "kv",                      # "kv" (key=value pairs) or "regex"
      "pattern": null,                   # regex: named groups; kv: optional line filter
      "timestamp": {"fields": ["date", "time", "tz"], "format": "%Y-%m-%d %H:%M:%S %z"},
      "action": "network_connection",
      "outcome": {"field": "action", "success": ["accept", "close"], "failure": ["deny"]},
      "fields": {"src_ip": "srcip", "dst_ip": "dstip", "bytes_out": "sentbyte"},
      "message": "{srcip} -> {dstip}:{dstport}"
    }

timestamp.format is a strptime format, "iso8601", "epoch" or "epoch_ms".
fields maps an event field (user, src_ip, host, process, message) or an
extra field name to a captured name (regex group or key).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import statistics
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Iterable

from .models import Event, ParseGap, SourceContext
from .timeutil import UTC, localize, offset_label, parse_rfc3339, resolve_tz, to_utc

EVENT_FIELDS = ("user", "src_ip", "host", "process", "message")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
CAPTURE_RE = re.compile(r"^[A-Za-z_][\w.-]{0,63}$")
KV_RE = re.compile(r'(?<![\w.-])([A-Za-z_][\w.-]{0,63})=("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s"\']*)')
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][\w.-]{0,63})\}")
MAX_PATTERN = 2000
MAX_FIELDS = 40
MAX_TEMPLATE = 300


class RuleError(ValueError):
    pass


# ---------------------------------------------------------------- definitions

def canonical(definition: dict[str, Any]) -> bytes:
    return json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def rule_hash(definition: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(definition)).hexdigest()


def _str_list(value: Any, what: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise RuleError(f"{what} must be a list of strings")
    return value


def validate(definition: Any) -> dict[str, Any]:
    """Check a rule definition and return it normalised; raise RuleError on problems."""
    if not isinstance(definition, dict):
        raise RuleError("a rule must be a JSON object")
    known = {"name", "source_ids", "mode", "pattern", "timestamp", "action", "outcome", "fields", "message"}
    unknown = set(definition) - known
    if unknown:
        raise RuleError(f"unknown rule keys: {', '.join(sorted(unknown))}")

    name = str(definition.get("name") or "").strip()
    if not name or len(name) > 80:
        raise RuleError("give the rule a name of 1 to 80 characters")
    source_ids = _str_list(definition.get("source_ids"), "source_ids")
    if not source_ids or not all(re.fullmatch(r"S\d{3,}", s) for s in source_ids):
        raise RuleError("source_ids must name one or more sources, such as S003")
    mode = definition.get("mode")
    if mode not in ("kv", "regex"):
        raise RuleError('mode must be "kv" or "regex"')

    pattern = definition.get("pattern")
    groups: set[str] = set()
    if pattern is not None:
        if not isinstance(pattern, str) or len(pattern) > MAX_PATTERN:
            raise RuleError(f"pattern must be a string of at most {MAX_PATTERN} characters")
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise RuleError(f"pattern is not a valid regular expression: {exc}") from None
        groups = set(compiled.groupindex)
    if mode == "regex" and not groups:
        raise RuleError("a regex rule needs a pattern with named groups, such as (?P<ts>...)")

    ts = definition.get("timestamp")
    if not isinstance(ts, dict) or set(ts) - {"fields", "format"}:
        raise RuleError('timestamp must be {"fields": [...], "format": "..."}')
    ts_fields = _str_list(ts.get("fields"), "timestamp.fields")
    if not 1 <= len(ts_fields) <= 4:
        raise RuleError("timestamp.fields must name 1 to 4 captured values")
    ts_format = ts.get("format")
    if not isinstance(ts_format, str) or not ts_format.strip() or len(ts_format) > 80:
        raise RuleError("timestamp.format must be a strptime format, iso8601, epoch or epoch_ms")
    if ts_format not in ("iso8601", "epoch", "epoch_ms") and "%" not in ts_format:
        raise RuleError("timestamp.format must contain strptime directives such as %Y-%m-%d %H:%M:%S")

    action = definition.get("action")
    if not isinstance(action, str) or not NAME_RE.match(action):
        raise RuleError("action must be a short lower_case name, such as network_connection")

    outcome = definition.get("outcome")
    if outcome is not None:
        if not isinstance(outcome, dict) or set(outcome) - {"field", "success", "failure"}:
            raise RuleError('outcome must be {"field": ..., "success": [...], "failure": [...]}')
        if not isinstance(outcome.get("field"), str) or not CAPTURE_RE.match(outcome["field"]):
            raise RuleError("outcome.field must name a captured value")
        outcome = {"field": outcome["field"],
                   "success": [v.lower() for v in _str_list(outcome.get("success", []), "outcome.success")],
                   "failure": [v.lower() for v in _str_list(outcome.get("failure", []), "outcome.failure")]}

    fields = definition.get("fields") or {}
    if not isinstance(fields, dict) or len(fields) > MAX_FIELDS:
        raise RuleError(f"fields must map at most {MAX_FIELDS} field names to captured names")
    for target, captured in fields.items():
        if not NAME_RE.match(target):
            raise RuleError(f"field name {target!r} must be lower_case letters, digits and _")
        if not isinstance(captured, str) or not CAPTURE_RE.match(captured):
            raise RuleError(f"field {target!r} must map to a captured name")

    message = definition.get("message")
    if message is not None and (not isinstance(message, str) or len(message) > MAX_TEMPLATE):
        raise RuleError(f"message must be a template of at most {MAX_TEMPLATE} characters")

    if mode == "regex":
        needed = set(ts_fields) | set(fields.values()) | ({outcome["field"]} if outcome else set())
        needed |= set(PLACEHOLDER_RE.findall(message or ""))
        missing = needed - groups
        if missing:
            raise RuleError(f"the pattern has no named group for: {', '.join(sorted(missing))}")

    return {"name": name, "source_ids": sorted(set(source_ids)), "mode": mode, "pattern": pattern,
            "timestamp": {"fields": ts_fields, "format": ts_format}, "action": action,
            "outcome": outcome, "fields": dict(fields), "message": message}


# ---------------------------------------------------------------- applying

def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        inner = value[1:-1]
        return re.sub(r'\\(.)', r"\1", inner) if value[0] == '"' else inner
    return value


def capture(rule: dict[str, Any], line: str) -> dict[str, str] | None:
    """The named values a rule captures from a line, or None when it does not apply."""
    values: dict[str, str] = {}
    if rule["pattern"] is not None:
        m = re.search(rule["pattern"], line)
        if not m:
            return None
        values.update({k: v for k, v in m.groupdict().items() if v is not None})
    if rule["mode"] == "kv":
        for key, value in KV_RE.findall(line):
            values.setdefault(key, _unquote(value))
    if not all(f in values for f in rule["timestamp"]["fields"]):
        return None
    return values


def parse_timestamp(rule: dict[str, Any], values: dict[str, str], ctx: SourceContext
                    ) -> tuple[datetime, str, str, bool, bool, bool]:
    """Return (aware ts, raw text, zone label, tz_assumed, year_inferred, dst_ambiguous)."""
    fmt = rule["timestamp"]["format"]
    raw = " ".join(values[f] for f in rule["timestamp"]["fields"])
    if fmt in ("epoch", "epoch_ms"):
        try:
            seconds = float(raw) / (1000 if fmt == "epoch_ms" else 1)
            return datetime.fromtimestamp(seconds, UTC), raw, "UTC", False, False, False
        except (ValueError, OverflowError, OSError) as exc:
            raise ValueError(f"not a Unix time: {raw!r}") from exc
    parsed = parse_rfc3339(raw.replace(" ", "T", 1) if re.match(r"\d{4}-\d\d-\d\d \d", raw) else raw) \
        if fmt == "iso8601" else datetime.strptime(raw, fmt)
    year_inferred = False
    if fmt != "iso8601" and not re.search(r"%[Yy]", fmt):
        ref = ctx.reference_time or datetime.now(UTC)
        year = ctx.year or ref.year
        parsed = parsed.replace(year=year)
        if ctx.year is None and parsed.replace(tzinfo=None) > ref.replace(tzinfo=None) + timedelta(days=1):
            parsed = parsed.replace(year=year - 1)
        year_inferred = ctx.year is None
    if parsed.tzinfo is not None:
        return parsed, raw, offset_label(parsed), False, year_inferred, False
    aware, ambiguous = localize(parsed, resolve_tz(ctx.tz))
    return aware, raw, ctx.tz, ctx.tz_assumed, year_inferred, ambiguous


def _typed(value: str) -> Any:
    return int(value) if re.fullmatch(r"-?\d{1,18}", value) else value


def _render(template: str, values: dict[str, str]) -> str:
    return PLACEHOLDER_RE.sub(lambda m: values.get(m.group(1)) or "-", template)


def to_event(rule_id: str, rule: dict[str, Any], gap: ParseGap, values: dict[str, str],
             ctx: SourceContext) -> Event:
    ts, raw_ts, zone, assumed, year_inferred, ambiguous = parse_timestamp(rule, values, ctx)
    event_fields: dict[str, Any] = {}
    extra: dict[str, Any] = {"parser_rule": rule_id}
    for target, captured in rule["fields"].items():
        value = values.get(captured)
        if value in (None, "", "-"):
            continue
        if target in EVENT_FIELDS:
            event_fields[target] = value
        else:
            extra[target] = _typed(value)
    src_ip = event_fields.pop("src_ip", None)
    if src_ip is not None:
        try:
            src_ip = str(ipaddress.ip_address(src_ip))
        except ValueError:
            extra["src"] = src_ip
            src_ip = None
    outcome = None
    if rule["outcome"]:
        verdict = (values.get(rule["outcome"]["field"]) or "").lower()
        outcome = "success" if verdict in rule["outcome"]["success"] else \
            "failure" if verdict in rule["outcome"]["failure"] else None
        if verdict:
            extra.setdefault("result", verdict)
    if ambiguous:
        extra["dst_ambiguous"] = True
    message = event_fields.pop("message", None)
    if rule["message"]:
        message = _render(rule["message"], values)
    return Event(
        ts_utc=to_utc(ts), ts_raw=raw_ts, source_id=ctx.source_id, source_type=ctx.source_type,
        source_file=ctx.source_file, file_sha256=ctx.file_sha256, line_no=gap.line_no,
        raw_line=gap.raw_line, host=event_fields.get("host") or ctx.host, process=event_fields.get("process"),
        user=event_fields.get("user"), src_ip=src_ip, action=rule["action"], outcome=outcome,
        message=message, tz=zone, tz_assumed=assumed, year_inferred=year_inferred, extra=extra,
    )


def apply_rules(result: Any, ctx: SourceContext, rules: list[tuple[str, dict[str, Any]]]) -> dict[str, int]:
    """Turn a ParseResult's gaps into events where an approved rule applies.

    Lines no rule matches stay gaps. A line a rule matches but cannot read
    a time from stays a gap with that reason. Returns events added per rule.
    """
    applicable = [(rid, r) for rid, r in rules if ctx.source_id in r["source_ids"]]
    counts: dict[str, int] = {}
    if not applicable or not result.gaps:
        return counts
    remaining = []
    for gap in result.gaps:
        event = None
        reason = gap.reason
        for rule_id, rule in applicable:
            values = capture(rule, gap.raw_line)
            if values is None:
                continue
            try:
                event = to_event(rule_id, rule, gap, values, ctx)
            except (ValueError, OverflowError) as exc:
                reason = f"parser rule {rule_id} matched but its timestamp did not parse: {exc}"
                continue
            counts[rule_id] = counts.get(rule_id, 0) + 1
            break
        if event is None:
            remaining.append(ParseGap(gap.source_id, gap.source_file, gap.file_sha256, gap.line_no,
                                      gap.raw_line, reason))
        else:
            result.events.append(event)
    result.events.sort(key=lambda e: e.line_no)
    result.gaps = remaining
    return counts


def dry_run(rule: dict[str, Any], gaps: Iterable[ParseGap], ctx_for: Any, sample: int = 8) -> dict[str, Any]:
    """Dry-run a rule over gap lines: how many it would parse, and examples of each outcome."""
    matched, unmatched, failed = 0, 0, 0
    examples: list[dict[str, Any]] = []
    misses: list[dict[str, Any]] = []
    tested = 0
    for gap in gaps:
        if gap.source_id not in rule["source_ids"]:
            continue
        tested += 1
        values = capture(rule, gap.raw_line)
        if values is None:
            unmatched += 1
            if len(misses) < sample:
                misses.append({"line_no": gap.line_no, "source_id": gap.source_id, "raw_line": gap.raw_line,
                               "problem": "the rule does not match this line"})
            continue
        try:
            event = to_event("TEST", rule, gap, values, ctx_for(gap.source_id))
        except (ValueError, OverflowError) as exc:
            failed += 1
            if len(misses) < sample:
                misses.append({"line_no": gap.line_no, "source_id": gap.source_id, "raw_line": gap.raw_line,
                               "problem": f"timestamp did not parse: {exc}"})
            continue
        matched += 1
        if len(examples) < sample:
            d = event.to_dict()
            d["extra"].pop("parser_rule", None)
            examples.append({k: d[k] for k in ("event_id", "line_no", "ts_utc", "ts_raw", "tz", "tz_assumed",
                                               "year_inferred", "host", "user", "src_ip", "action", "outcome",
                                               "message", "extra", "raw_line")})
    return {"lines_tested": tested, "lines_parsed": matched, "lines_unmatched": unmatched,
            "timestamp_failures": failed, "examples": examples, "problems": misses}


# ---------------------------------------------------------------- custody

def active_rules(case: Any) -> list[tuple[str, dict[str, Any]]]:
    """Approved, unrevoked rules from the custody log, in approval order."""
    rules: dict[str, dict[str, Any]] = {}
    for record in case.read_custody():
        if record.get("action") == "approve_parser_rule":
            definition = record.get("definition") or {}
            if rule_hash(definition) == record.get("rule_sha256"):
                rules[record["rule_id"]] = definition
        elif record.get("action") == "revoke_parser_rule":
            rules.pop(record.get("rule_id"), None)
    return list(rules.items())


def rule_records(case: Any) -> list[dict[str, Any]]:
    """Every rule ever approved, with who approved it and whether it is still active."""
    out: dict[str, dict[str, Any]] = {}
    for record in case.read_custody():
        if record.get("action") == "approve_parser_rule":
            out[record["rule_id"]] = {
                "rule_id": record["rule_id"], "rule_sha256": record.get("rule_sha256"),
                "definition": record.get("definition"), "approved_by": record.get("actor"),
                "approved_utc": record.get("ts_utc"), "custody_seq": record.get("seq"),
                "test": record.get("test"), "active": True,
            }
        elif record.get("action") == "revoke_parser_rule" and record.get("rule_id") in out:
            out[record["rule_id"]].update(active=False, revoked_by=record.get("actor"),
                                          revoked_utc=record.get("ts_utc"), revoke_reason=record.get("reason"))
    return list(out.values())


def approve(case: Any, definition: dict[str, Any], test: dict[str, Any], actor: str | None = None) -> dict[str, Any]:
    """Record an approved rule in the custody log; the next parse applies it."""
    known = {s["source_id"] for s in case.sources()}
    missing = set(definition["source_ids"]) - known
    if missing:
        raise RuleError(f"unknown source(s): {', '.join(sorted(missing))}")
    if not test.get("lines_parsed"):
        raise RuleError("the rule does not parse any unparsed line yet; test and adjust it before approving")
    rule_id = f"R{len(rule_records(case)) + 1:03d}"
    summary = {k: test[k] for k in ("lines_tested", "lines_parsed", "lines_unmatched", "timestamp_failures")}
    return case.append_custody("approve_parser_rule", actor, rule_id=rule_id, rule_sha256=rule_hash(definition),
                               source_ids=definition["source_ids"], definition=definition, test=summary)


def revoke(case: Any, rule_id: str, actor: str | None = None, reason: str = "") -> dict[str, Any]:
    if rule_id not in dict(active_rules(case)):
        raise RuleError(f"{rule_id} is not an active parser rule")
    return case.append_custody("revoke_parser_rule", actor, rule_id=rule_id, reason=reason)


# ---------------------------------------------------------------- suggesting

# Timestamp shapes the assistant recognises: (regex, strptime format or keyword, label).
TIMESTAMP_SHAPES: list[tuple[str, str, str]] = [
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?", "iso8601", "ISO 8601"),
    (r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", "%Y/%m/%d %H:%M:%S", "YYYY/MM/DD hh:mm:ss"),
    (r"\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}", "%d/%b/%Y:%H:%M:%S %z", "Common Log Format"),
    (r"\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}", "%d-%b-%Y %H:%M:%S", "DD-Mon-YYYY hh:mm:ss"),
    (r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}", "%m/%d/%Y %H:%M:%S", "NN/NN/YYYY hh:mm:ss"),
    (r"[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}", "%b %d %H:%M:%S", "Mon DD hh:mm:ss (no year)"),
    (r"1\d{12}", "epoch_ms", "Unix time, milliseconds"),
    (r"1\d{9}(?:\.\d{1,6})?", "epoch", "Unix time, seconds"),
]

# Common key names in key=value logs (FortiGate, Palo Alto, Check Point, iptables, Windows-style
# exports), mapped to ORISECT field names.
KEY_ALIASES: dict[str, tuple[str, ...]] = {
    "src_ip": ("srcip", "src_ip", "src", "source_ip", "sourceip", "saddr", "client_ip", "clientip", "ip",
               "remote_ip", "remote_addr", "rhost"),
    "dst_ip": ("dstip", "dst_ip", "dst", "destination_ip", "destip", "daddr", "server_ip"),
    "src_port": ("srcport", "src_port", "spt", "sport", "source_port"),
    "dst_port": ("dstport", "dst_port", "dpt", "dport", "destination_port"),
    "bytes_out": ("sentbyte", "sent_bytes", "bytes_out", "bytesout", "out_bytes", "tx_bytes", "bytes_sent", "sent"),
    "bytes_in": ("rcvdbyte", "rcvd_bytes", "bytes_in", "bytesin", "in_bytes", "rx_bytes", "bytes_received", "rcvd"),
    "user": ("user", "username", "usr", "srcuser", "suser", "account", "login"),
    "host": ("devname", "hostname", "host", "device", "dvchost", "computer"),
    "process": ("process", "program", "app", "appname", "proc"),
    "protocol": ("proto", "protocol", "ipproto"),
    "service": ("service", "app_service"),
    "duration_s": ("duration", "elapsed", "session_duration"),
    "policy": ("policyid", "policy", "rule", "rule_name", "policy_id"),
    "url": ("url", "uri", "request"),
    "event_type": ("subtype", "type", "event_type", "category"),
}
OUTCOME_KEYS = ("action", "act", "disposition", "result", "outcome", "status", "verdict")
SUCCESS_WORDS = {"accept", "accepted", "allow", "allowed", "permit", "permitted", "pass", "passed", "close",
                 "closed", "success", "succeeded", "ok", "timeout", "server-rst", "client-rst", "start", "built"}
FAILURE_WORDS = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "fail", "failed",
                 "failure", "teardown-deny", "reset-both", "error"}
TZ_KEYS = ("tz", "timezone", "utcoffset")
LEVEL_WORDS = {"trace", "debug", "info", "notice", "warn", "warning", "error", "err", "crit", "critical", "alert",
               "emerg", "fatal", "severe"}
TOKEN_KV_RE = re.compile(r"^([A-Za-z_][\w.-]{0,63})=(\S*)$")


def _shape_of(text: str) -> tuple[str, str, str] | None:
    for regex, fmt, label in TIMESTAMP_SHAPES:
        if re.fullmatch(regex, text):
            return regex, fmt, label
    return None


def _explicit(fmt: str, value: str) -> str:
    """Spell out a plain ISO date-time as a strptime format, so a separate offset key can be added."""
    if fmt == "iso8601":
        m = re.fullmatch(r"\d{4}-\d{2}-\d{2}([T ])\d{2}:\d{2}:\d{2}", value)
        if m:
            return f"%Y-%m-%d{m.group(1)}%H:%M:%S"
    return fmt


def _date_order(values: list[str], fmt: str) -> str:
    """Pick day-first when MM/DD values cannot be months."""
    if fmt == "%m/%d/%Y %H:%M:%S" and any(int(v[:2]) > 12 for v in values if v[:2].isdigit()):
        return "%d/%m/%Y %H:%M:%S"
    return fmt


def _suggest_kv(lines: list[str], source_ids: list[str], name: str) -> tuple[dict[str, Any], list[str]] | None:
    parsed = [dict((k, _unquote(v)) for k, v in KV_RE.findall(line)) for line in lines]
    counts = [len(p) for p in parsed]
    coverage = [sum(len(m.group(0)) for m in KV_RE.finditer(line)) / max(len(line), 1) for line in lines]
    if statistics.median(counts) < 3 or statistics.median(coverage) < 0.45:
        return None
    key_freq = Counter(k for p in parsed for k in p)
    common = [k for k, n in key_freq.items() if n >= len(lines) * 0.5]
    lower = {k.lower(): k for k in common}
    notes: list[str] = []

    # Timestamp: a date + time pair, or one key whose values all look like one timestamp shape.
    ts_fields: list[str] | None = None
    ts_format = ""
    if "date" in lower and "time" in lower:
        sample = f"{parsed[0].get(lower['date'], '')} {parsed[0].get(lower['time'], '')}"
        shape = _shape_of(sample)
        if shape:
            ts_fields, ts_format = [lower["date"], lower["time"]], _explicit(shape[1], sample)
            notes.append(f"Time is split across the {lower['date']} and {lower['time']} keys ({shape[2]}).")
    if ts_fields is None:
        for key in common:
            values = [p[key] for p in parsed if key in p]
            shapes = {(_shape_of(v) or ("", "", ""))[1] for v in values}
            if len(shapes) == 1 and "" not in shapes:
                shape = _shape_of(values[0])
                ts_fields, ts_format = [key], _explicit(_date_order(values, shape[1]), values[0])
                notes.append(f"Time comes from the {key} key ({shape[2]}).")
                break
    prefix_pattern = None
    if ts_fields is None:
        prefix = _leading_timestamp(lines)
        if prefix is None:
            return None
        regex, ts_format, label = prefix
        prefix_pattern = rf"^(?P<ts>{regex})\s"
        ts_fields = ["ts"]
        notes.append(f"Time comes from the start of each line ({label}).")
    tz_key = next((lower[k] for k in TZ_KEYS if k in lower), None)
    if tz_key and ts_format not in ("iso8601", "epoch", "epoch_ms") and "%z" not in ts_format and \
            all(re.fullmatch(r"[+-]\d{4}", p.get(tz_key, "")) for p in parsed if tz_key in p):
        ts_fields.append(tz_key)
        ts_format += " %z"
        notes.append(f"The {tz_key} key gives each line's UTC offset, so no time zone has to be assumed.")
    if ts_format == "iso8601" or "%z" in ts_format or ts_format.startswith("epoch"):
        pass
    else:
        notes.append("Lines carry no UTC offset: the source's time zone setting is used.")

    used = set(ts_fields)
    fields: dict[str, str] = {}
    for target, aliases in KEY_ALIASES.items():
        key = next((lower[a] for a in aliases if a in lower and lower[a] not in used), None)
        if key:
            fields[target] = key
            used.add(key)
    outcome = None
    for k in OUTCOME_KEYS:
        if k in lower and lower[k] not in used:
            seen = {p[lower[k]].lower() for p in parsed if lower[k] in p}
            success, failure = sorted(seen & SUCCESS_WORDS), sorted(seen & FAILURE_WORDS)
            if success or failure:
                outcome = {"field": lower[k], "success": success, "failure": failure}
                unknown = sorted(seen - SUCCESS_WORDS - FAILURE_WORDS)
                notes.append(f"Outcome comes from {lower[k]}: " + ", ".join(
                    part for part in (f"{'/'.join(success)} = success" if success else "",
                                      f"{'/'.join(failure)} = failure" if failure else "",
                                      f"{'/'.join(unknown)} = unknown" if unknown else "") if part) + ".")
                break
    network = "dst_ip" in fields and ("src_ip" in fields or "dst_port" in fields)
    action = "network_connection" if network else "log_event"
    if network:
        f = fields
        message = "{%s}" % f["src_ip"] if "src_ip" in f else "?"
        message += (":{%s}" % f["src_port"]) if "src_port" in f else ""
        message += " -> {%s}" % f["dst_ip"] + ((":{%s}" % f["dst_port"]) if "dst_port" in f else "")
        message += (" {%s}" % f["service"]) if "service" in f else ""
        message += (" {%s}" % outcome["field"]) if outcome else ""
        if "bytes_out" in f:
            message += ", sent {%s} B" % f["bytes_out"]
        if "bytes_in" in f:
            message += ", received {%s} B" % f["bytes_in"]
    else:
        shown = [k for k in common if k not in set(ts_fields)][:5]
        message = " ".join("%s={%s}" % (k, k) for k in shown)
    skipped = sorted(set(common) - used - ({outcome["field"]} if outcome else set()))
    if skipped:
        notes.append("Not mapped (still visible in the original line): " + ", ".join(skipped) + ".")
    return {"name": name, "source_ids": source_ids, "mode": "kv", "pattern": prefix_pattern,
            "timestamp": {"fields": ts_fields, "format": ts_format}, "action": action,
            "outcome": outcome, "fields": fields, "message": message}, notes


def _leading_timestamp(lines: list[str]) -> tuple[str, str, str] | None:
    for regex, fmt, label in TIMESTAMP_SHAPES:
        hits = [re.match(rf"(?:<\d{{1,3}}>)?\[?({regex})\]?(?=[\s,;|]|$)", line) for line in lines]
        if sum(bool(h) for h in hits) >= max(1, int(len(lines) * 0.8)):
            values = [h.group(1) for h in hits if h]
            return regex, _date_order(values, fmt), label
    return None


TOKEN_TYPES = [
    ("ip", r"(?:\d{1,3}\.){3}\d{1,3}"),
    ("num", r"-?\d+"),
    ("word", r"\S+"),
]


def _alias_for(key: str) -> str | None:
    k = key.lower()
    return next((target for target, aliases in KEY_ALIASES.items() if k in aliases), None)


def _suggest_regex(lines: list[str], source_ids: list[str], name: str) -> tuple[dict[str, Any], list[str]] | None:
    found = _leading_timestamp(lines)
    if found is None:
        return None
    regex, ts_format, label = found
    notes = [f"Time comes from the start of each line ({label})."]
    if ts_format == "%d/%m/%Y %H:%M:%S":
        notes.append("Dates are day-first (DD/MM/YYYY): some lines have a first number above 12.")
    elif ts_format == "%m/%d/%Y %H:%M:%S":
        notes.append("Dates are read month-first (MM/DD/YYYY); no line proves otherwise, so check one by hand.")
    if ts_format == "%b %d %H:%M:%S":
        notes.append("The year is missing: it is inferred, and every event is flagged.")
    elif not (ts_format == "iso8601" or "%z" in ts_format or ts_format.startswith("epoch")):
        notes.append("Lines carry no UTC offset: the source's time zone setting is used.")
    head = re.compile(rf"^(?:<\d{{1,3}}>)?\[?(?:{regex})\]?[\s,;|]*")
    rests = [head.sub("", line, count=1) for line in lines if head.match(line)]
    token_lists = [r.split() for r in rests]
    lengths = Counter(len(t) for t in token_lists)
    common_len, _ = lengths.most_common(1)[0]
    parts: list[str] = []
    fields: dict[str, str] = {}
    counters: Counter[str] = Counter()

    def claim(target: str, group: str) -> None:
        fields[target if target not in fields else group] = group

    if 1 <= common_len <= 16 and lengths[common_len] >= len(token_lists) * 0.8:
        columns = list(zip(*[t for t in token_lists if len(t) == common_len]))
        for i, column in enumerate(columns):
            kv = [TOKEN_KV_RE.match(c) for c in column]
            if all(kv) and len({m.group(1) for m in kv}) == 1:
                key = kv[0].group(1)
                group = re.sub(r"[^A-Za-z0-9_]", "_", key)
                group = group if group not in counters else f"{group}_{i}"
                counters[group] += 1
                parts.append(rf"{re.escape(key)}=(?P<{group}>\S*)")
                claim(_alias_for(key) or group.lower(), group)
                continue
            if len(set(column)) == 1 and i < common_len - 1:
                parts.append(re.escape(column[0]))
                continue
            if i == common_len - 1 and len(set(column)) > 1 and not all(re.fullmatch(r"-?\d+", c) for c in column):
                parts.append(r"(?P<message>.+)")
                break
            kind = next(k for k, pat in TOKEN_TYPES if all(re.fullmatch(pat, c) for c in column))
            if kind == "word" and all(c.strip("[]:").lower() in LEVEL_WORDS for c in column):
                kind = "level"
            counters[kind] += 1
            group = kind if kind == "level" and counters[kind] == 1 else f"{kind}{counters[kind]}"
            parts.append(rf"(?P<{group}>{dict(TOKEN_TYPES).get(kind, r'\S+')})")
            if kind == "ip":
                claim("src_ip" if "src_ip" not in fields else "dst_ip", group)
            elif i == 0 and kind == "word" and all(re.fullmatch(r"[a-z][a-z0-9.-]*", c) for c in column):
                fields["host"] = group
            else:
                fields[group] = group
        body = r"\s+".join(parts)
        notes.append(f"Every line has the same {common_len} parts: fixed parts are matched literally, "
                     "changing ones are captured, and key=value parts keep their key as the name.")
    else:
        body = r"(?P<message>.+)"
        notes.append("Lines differ in shape, so the rest of each line is kept as the message.")
    pattern = rf"^(?:<\d{{1,3}}>)?\[?(?P<ts>{regex})\]?[\s,;|]+{body}$"
    message = "{message}" if "(?P<message>" in pattern else " ".join("{%s}" % g for g in fields.values())
    fields.pop("message", None)
    outcome = None
    if "level" in fields.values():
        outcome = {"field": "level", "success": [], "failure": ["error", "err", "crit", "critical", "fatal", "alert", "emerg"]}
    return {"name": name, "source_ids": source_ids, "mode": "regex", "pattern": pattern,
            "timestamp": {"fields": ["ts"], "format": ts_format}, "action": "log_event",
            "outcome": outcome, "fields": fields, "message": message}, notes


def suggest(lines: list[str], source_ids: list[str], name: str = "") -> dict[str, Any]:
    """Propose a rule from sample lines, explaining each choice. Purely structural; never guesses meaning
    beyond well-known field names."""
    sample = [line for line in lines if line.strip()][:200]
    if not sample:
        raise RuleError("there are no unparsed lines to learn from")
    name = name or f"{', '.join(source_ids)} format"
    for attempt in (_suggest_kv, _suggest_regex):
        proposal = attempt(sample, source_ids, name)
        if proposal:
            definition, notes = proposal
            definition = validate(definition)
            return {"definition": definition, "notes": notes, "lines_considered": len(sample)}
    raise RuleError("no timestamp was found in a consistent position, so no rule can be proposed; "
                    "write the pattern by hand")
