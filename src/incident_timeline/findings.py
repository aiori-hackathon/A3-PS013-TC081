"""Explainable leads over a normalised timeline.

Each rule is a small, deterministic check over event dicts (the
events.jsonl contract). A finding names the rule that fired, why it fired,
the MITRE ATT&CK technique it resembles, and the exact event IDs
(source:line) behind it, so every claim can be traced to a collected line.

Findings are leads for an analyst to review. They do not prove that an
attack happened or that one event caused another.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Iterable

from .timeutil import parse_rfc3339, to_rfc3339

SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}

AUTH_FAILURE_ACTIONS = {"ssh_login", "ssh_invalid_user", "ssh_max_auth_exceeded", "auth_failure"}
BRUTE_FORCE_MIN = 3
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
LOGIN_AFTER_FAILURE_WINDOW = timedelta(hours=1)
WEB_TO_SSH_WINDOW = timedelta(hours=2)
PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "adm", "root"}
OUTBOUND_MIN_BYTES = 10_000_000
OUTBOUND_MIN_CONNECTION_BYTES = 100_000  # smaller connections (beacons, NTP, DNS) are not part of a bulk transfer
OUTBOUND_WINDOW = timedelta(hours=1)
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")]

SENSITIVE_FILE_RE = re.compile(r"/etc/(?:shadow|gshadow|sudoers)\b|/root/\.ssh/|id_rsa\b")
WEB_SHELL_RE = re.compile(r"\.(?:php\d?|phtml|jsp|aspx?)\b[^ ]*[?&](?:cmd|exec|command|c)=", re.I)
UPLOADED_SCRIPT_RE = re.compile(r"/uploads?/[^ ?]*\.(?:php\d?|phtml|jsp|aspx?)\b", re.I)
PROBE_PATH_RE = re.compile(r"wp-login|wp-admin|/admin\b|/\.env\b|/\.git\b|phpmyadmin|/etc/passwd|\.\./", re.I)
SUSPICIOUS_CRON_RE = re.compile(r"(?:^|\s)(?:/tmp|/var/tmp|/dev/shm)/|/\.[^/\s]+/|\b(?:curl|wget|nc|ncat)\b|bash -c", re.I)

RULES: dict[str, dict[str, str]] = {
    "brute_force": {
        "technique": "T1110", "technique_name": "Brute Force",
        "rationale": f"{BRUTE_FORCE_MIN} or more failed authentications from one address within "
                     f"{int(BRUTE_FORCE_WINDOW.total_seconds() // 60)} minutes.",
    },
    "login_after_failures": {
        "technique": "T1078", "technique_name": "Valid Accounts",
        "rationale": "A successful SSH login from an address that failed to authenticate in the hour before.",
    },
    "web_to_ssh": {
        "technique": "T1021.004", "technique_name": "Remote Services: SSH",
        "rationale": "The same client address appears in a web access log and then logs in over SSH, "
                     "in different evidence sources, within two hours.",
    },
    "web_shell": {
        "technique": "T1505.003", "technique_name": "Server Software Component: Web Shell",
        "rationale": "A request runs a command through a script parameter (cmd=, exec=) or calls a script "
                     "from an upload folder.",
    },
    "web_probing": {
        "technique": "T1595", "technique_name": "Active Scanning",
        "rationale": "Two or more refused requests (4xx) from one address for login pages, admin paths or "
                     "configuration files.",
    },
    "sensitive_file_access": {
        "technique": "T1003.008", "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "rationale": "A privileged command touches a credential store such as /etc/shadow or /etc/sudoers.",
    },
    "privileged_commands": {
        "technique": "T1548.003", "technique_name": "Abuse Elevation Control: Sudo",
        "rationale": "Commands run through sudo as another user (usually root).",
    },
    "account_created": {
        "technique": "T1136.001", "technique_name": "Create Account: Local Account",
        "rationale": "A local account was created; it is flagged high when it is also added to an administrative group.",
    },
    "suspicious_cron": {
        "technique": "T1053.003", "technique_name": "Scheduled Task/Job: Cron",
        "rationale": "A cron job runs from a temporary or hidden directory, or downloads or pipes code.",
    },
    "large_outbound_transfer": {
        "technique": "T1048", "technique_name": "Exfiltration Over Alternative Protocol",
        "rationale": f"An internal host sent {OUTBOUND_MIN_BYTES // 1_000_000} MB or more to one external address "
                     f"within {int(OUTBOUND_WINDOW.total_seconds() // 3600)} hour, counting connections of "
                     f"{OUTBOUND_MIN_CONNECTION_BYTES // 1000} KB or more, in a log that records bytes sent "
                     "(such as a firewall).",
    },
    "time_basis": {
        "technique": "", "technique_name": "",
        "rationale": "Some timestamps rely on an assumed time zone or an inferred year; ordering against other "
                     "sources may be off.",
    },
}


def _ts(event: dict[str, Any]) -> datetime | None:
    try:
        return parse_rfc3339(str(event.get("ts_utc") or ""))
    except (ValueError, TypeError):
        return None


def _finding(rule: str, severity: str, title: str, summary: str, events: Iterable[dict[str, Any]],
             **entities: Iterable[str | None]) -> dict[str, Any]:
    evs = sorted({e["event_id"]: e for e in events}.values(), key=lambda e: (e.get("ts_utc") or "", e["event_id"]))
    stamps = [t for t in (_ts(e) for e in evs) if t]
    return {
        "id": f"{rule}:{evs[0]['event_id']}" if evs else rule,
        "rule": rule,
        "severity": severity,
        "title": title,
        "summary": summary,
        "technique": RULES[rule]["technique"],
        "technique_name": RULES[rule]["technique_name"],
        "rationale": RULES[rule]["rationale"],
        "first_ts_utc": to_rfc3339(min(stamps)) if stamps else None,
        "last_ts_utc": to_rfc3339(max(stamps)) if stamps else None,
        "event_ids": [e["event_id"] for e in evs],
        "entities": {k: sorted({v for v in vals if v}) for k, vals in entities.items()},
    }


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _span(events: list[dict[str, Any]]) -> str:
    stamps = [t for t in (_ts(e) for e in events) if t]
    if len(stamps) < 2:
        return ""
    seconds = int((max(stamps) - min(stamps)).total_seconds())
    if seconds < 120:
        return f" in {seconds} s"
    return f" in {seconds // 60} min"


def _is_auth_failure(e: dict[str, Any]) -> bool:
    return e.get("action") in AUTH_FAILURE_ACTIONS and e.get("outcome") == "failure"


def _web_path(e: dict[str, Any]) -> str:
    extra = e.get("extra") or {}
    return str(extra.get("path") or e.get("message") or "")


def _command(e: dict[str, Any]) -> str:
    extra = e.get("extra") or {}
    return str(extra.get("command") or e.get("message") or "")


def _brute_force(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if _is_auth_failure(e) and e.get("src_ip"):
            by_ip[e["src_ip"]].append(e)
    found = []
    for ip, fails in by_ip.items():
        stamps = [_ts(e) for e in fails]
        burst = any(
            sum(1 for t in stamps if t and start and start <= t <= start + BRUTE_FORCE_WINDOW) >= BRUTE_FORCE_MIN
            for start in stamps
        )
        if burst:
            users = sorted({e.get("user") for e in fails if e.get("user")})
            found.append(_finding(
                "brute_force", "medium", f"Repeated failed logins from {ip}",
                f"{_plural(len(fails), 'failed authentication')}{_span(fails)}"
                + (f" against {', '.join(users)}." if users else "."),
                fails, ips=[ip], users=users))
    return found


def _login_after_failures(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    found = []
    for i, e in enumerate(events):
        if not (e.get("action") == "ssh_login" and e.get("outcome") == "success" and e.get("src_ip")):
            continue
        t = _ts(e)
        if t is None:
            continue
        prior = [p for p in events[:i] if _is_auth_failure(p) and p.get("src_ip") == e["src_ip"]
                 and (pt := _ts(p)) is not None and t - LOGIN_AFTER_FAILURE_WINDOW <= pt <= t]
        if prior:
            found.append(_finding(
                "login_after_failures", "high", f"Login as {e.get('user') or 'unknown user'} after failed attempts",
                f"{e['src_ip']} logged in successfully after {_plural(len(prior), 'failed attempt')}.",
                prior + [e], ips=[e["src_ip"]], users=[e.get("user")] + [p.get("user") for p in prior]))
    return found


def _web_to_ssh(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    web: dict[str, list[dict[str, Any]]] = defaultdict(list)
    found = []
    for e in events:
        ip = e.get("src_ip")
        if not ip:
            continue
        if e.get("action") == "http_request":
            web[ip].append(e)
        elif e.get("action") == "ssh_login" and e.get("outcome") == "success" and ip in web:
            t = _ts(e)
            hits = [w for w in web[ip] if w.get("source_id") != e.get("source_id")
                    and t and (wt := _ts(w)) and t - WEB_TO_SSH_WINDOW <= wt <= t]
            if hits:
                found.append(_finding(
                    "web_to_ssh", "high", f"{ip} moved from web requests to SSH",
                    f"{_plural(len(hits), 'web request')} in {hits[0].get('source_file')} were followed by an SSH "
                    f"login as {e.get('user') or 'unknown user'} in {e.get('source_file')}.",
                    hits + [e], ips=[ip], users=[e.get("user")]))
                web[ip] = []  # report each pivot once
    return found


def _web_shell(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("action") != "http_request":
            continue
        path = _web_path(e)
        if WEB_SHELL_RE.search(path) or (UPLOADED_SCRIPT_RE.search(path) and e.get("outcome") == "success"):
            by_ip[e.get("src_ip") or "unknown"].append(e)
    found = []
    for ip, hits in by_ip.items():
        # Include an upload from the same address shortly before, if there is one.
        first = _ts(hits[0])
        uploads = [e for e in events if e.get("action") == "http_request" and e.get("src_ip") == ip
                   and (e.get("extra") or {}).get("method") == "POST" and "upload" in _web_path(e).lower()
                   and first and (ut := _ts(e)) and first - timedelta(hours=1) <= ut <= first]
        lead = f"An upload, then {_plural(len(hits), 'request')}" if uploads else _plural(len(hits), "request")
        found.append(_finding(
            "web_shell", "high", f"Possible web shell used from {ip}",
            f"{lead} to {', '.join(sorted({_web_path(h).split('?')[0] for h in hits}))}.",
            uploads + hits, ips=[ip]))
    return found


def _web_probing(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        status = (e.get("extra") or {}).get("status")
        if e.get("action") == "http_request" and isinstance(status, int) and 400 <= status < 500 \
                and PROBE_PATH_RE.search(_web_path(e)):
            by_ip[e.get("src_ip") or "unknown"].append(e)
    return [
        _finding("web_probing", "medium", f"Probing of admin and login paths from {ip}",
                 f"{_plural(len(hits), 'refused request')}{_span(hits)} to "
                 f"{', '.join(sorted({_web_path(h).split('?')[0] for h in hits}))}.",
                 hits, ips=[ip])
        for ip, hits in by_ip.items() if len(hits) >= 2
    ]


def _sudo(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sensitive, other = [], defaultdict(list)
    for e in events:
        if e.get("action") != "sudo_command":
            continue
        if SENSITIVE_FILE_RE.search(_command(e)):
            sensitive.append(e)
        else:
            other[e.get("user") or "unknown"].append(e)
    found = [
        _finding("sensitive_file_access", "high", f"{e.get('user') or 'A user'} accessed a credential file through sudo",
                 f"Command: {_command(e)}", [e], users=[e.get("user")])
        for e in sensitive
    ]
    for user, cmds in other.items():
        found.append(_finding(
            "privileged_commands", "info", f"{user} ran {_plural(len(cmds), 'command')} through sudo",
            "; ".join(_command(c) for c in cmds[:3]) + (" …" if len(cmds) > 3 else ""),
            cmds, users=[user]))
    return found


def _accounts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    created = {e.get("user"): e for e in events if e.get("action") == "user_created" and e.get("user")}
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("action") == "user_group_added" and e.get("user"):
            groups[e["user"]].append(e)
    found = []
    for user in sorted(set(created) | set(groups)):
        admin = [g for g in groups.get(user, []) if (g.get("extra") or {}).get("group") in PRIVILEGED_GROUPS]
        evs = ([created[user]] if user in created else []) + groups.get(user, [])
        if user in created and admin:
            title, severity = f"New account {user} given admin rights", "high"
            summary = f"{user} was created and added to {', '.join(sorted({(g.get('extra') or {}).get('group') for g in admin}))}."
        elif user in created:
            title, severity, summary = f"New local account {user}", "medium", f"{user} was created on {created[user].get('host') or 'the host'}."
        elif admin:
            title, severity = f"{user} added to an admin group", "high"
            summary = f"{user} was added to {', '.join(sorted({(g.get('extra') or {}).get('group') for g in admin}))}."
        else:
            continue
        found.append(_finding("account_created", severity, title, summary, evs, users=[user]))
    return found


def _cron(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _finding("suspicious_cron", "high", "Cron job runs from a hidden or temporary path",
                 f"{e.get('user') or 'cron'} ran: {_command(e)}", [e], users=[e.get("user")])
        for e in events if e.get("action") == "cron_command" and SUSPICIOUS_CRON_RE.search(_command(e))
    ]


def _internal(ip: str | None) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETWORKS if net.version == addr.version)


def _size(n: int) -> str:
    return f"{n / 1e6:.1f} MB" if n >= 1_000_000 else f"{n / 1e3:.1f} KB" if n >= 1_000 else f"{n} B"


def _outbound(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flows: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    per_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        extra = e.get("extra") or {}
        sent, src, dst = extra.get("bytes_out"), e.get("src_ip"), extra.get("dst_ip")
        if isinstance(sent, int) and src and dst and _internal(src) and not _internal(dst):
            per_host[src].append(e)
            if sent >= OUTBOUND_MIN_CONNECTION_BYTES:
                flows[(src, dst)].append(e)
    found = []
    for (src, dst), evs in flows.items():
        best: list[dict[str, Any]] = []
        for i, first in enumerate(evs):
            start = _ts(first)
            window = [x for x in evs[i:] if start and (t := _ts(x)) and t - start <= OUTBOUND_WINDOW]
            if sum(x["extra"]["bytes_out"] for x in window) > sum(x["extra"]["bytes_out"] for x in best):
                best = window
        total = sum(x["extra"]["bytes_out"] for x in best)
        if total < OUTBOUND_MIN_BYTES:
            continue
        chosen = {x["event_id"] for x in best}
        others = [x for x in per_host[src] if x["event_id"] not in chosen]
        summary = f"{_size(total)} sent from {src} to {dst} in {_plural(len(best), 'connection')}{_span(best)}."
        if others:
            summary += (f" Its other {_plural(len(others), 'outbound connection')} in this evidence sent "
                        f"{_size(sum(x['extra']['bytes_out'] for x in others))} in total.")
        elsewhere = sorted({str(x.get("source_file")) for x in events if x.get("src_ip") == dst
                            and x.get("source_id") not in {b.get("source_id") for b in best}})
        if elsewhere:
            summary += f" {dst} also appears in {', '.join(elsewhere)}."
        found.append(_finding("large_outbound_transfer", "high", f"Large upload from {src} to {dst}",
                              summary, best, ips=[src, dst]))
    return found


def _time_basis(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flagged = [e for e in events if e.get("tz_assumed") or e.get("year_inferred")]
    if not flagged:
        return []
    sources = sorted({e.get("source_id") for e in flagged if e.get("source_id")})
    parts = []
    if any(e.get("tz_assumed") for e in flagged):
        parts.append("time zone assumed")
    if any(e.get("year_inferred") for e in flagged):
        parts.append("year inferred")
    return [_finding("time_basis", "info", "Some timestamps are partly assumed",
                     f"{_plural(len(flagged), 'event')} in {', '.join(sources)}: {' and '.join(parts)}. "
                     "Set --tz or --year on collect to remove the assumption.",
                     flagged)]


DETECTORS = (_login_after_failures, _web_to_ssh, _web_shell, _outbound, _brute_force, _web_probing,
             _sudo, _accounts, _cron, _time_basis)


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run every rule over time-ordered event dicts; most severe first."""
    ordered = sorted(events, key=lambda e: (e.get("ts_utc") or "", e.get("source_id") or "", e.get("line_no") or 0))
    found = [f for detector in DETECTORS for f in detector(ordered)]
    found.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["first_ts_utc"] or ""))
    return found


def entities(events: list[dict[str, Any]], limit: int = 8) -> dict[str, list[dict[str, Any]]]:
    """The most active addresses and accounts, with where and when they were seen."""
    out: dict[str, list[dict[str, Any]]] = {}
    for kind, key in (("ips", "src_ip"), ("users", "user")):
        stats: dict[str, dict[str, Any]] = {}
        for e in events:
            value = e.get(key)
            if not value:
                continue
            s = stats.setdefault(value, {"value": value, "events": 0, "failures": 0, "sources": set(),
                                         "first_ts_utc": e.get("ts_utc"), "last_ts_utc": e.get("ts_utc")})
            s["events"] += 1
            s["failures"] += e.get("outcome") == "failure"
            s["sources"].add(e.get("source_id"))
            ts = e.get("ts_utc")
            if ts and (not s["first_ts_utc"] or ts < s["first_ts_utc"]):
                s["first_ts_utc"] = ts
            if ts and (not s["last_ts_utc"] or ts > s["last_ts_utc"]):
                s["last_ts_utc"] = ts
        ranked = sorted(stats.values(), key=lambda s: (-len(s["sources"]), -s["events"], s["value"]))[:limit]
        out[kind] = [{**s, "sources": sorted(x for x in s["sources"] if x)} for s in ranked]
    return out
