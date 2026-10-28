"""Deterministic synthetic incident scenarios for development and demonstrations.

The sample timestamps and log lines are fixed; each run recreates the same
normalized event order and event content. Custody records still receive real
collection timestamps, as they should in an evidence-handling workflow.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import time
from pathlib import Path
from typing import Any, Iterable

from .evidence import Case, collect, verify
from .pipeline import build_timeline

SCENARIOS: dict[str, dict[str, Any]] = {
    "01-brute-force-to-sudo": {
        "title": "Brute-force login followed by privileged access",
        "description": "Repeated SSH authentication failures are followed by a successful login, an opened session, and a command reading a sensitive file.",
        "host": "web01",
        "logs": {
            "auth.log": """Oct 21 09:00:01 web01 sshd[2001]: Failed password for invalid user admin from 203.0.113.77 port 52001 ssh2
Oct 21 09:00:03 web01 sshd[2001]: Failed password for root from 203.0.113.77 port 52001 ssh2
Oct 21 09:00:08 web01 sshd[2001]: error: maximum authentication attempts exceeded for root from 203.0.113.77 port 52001
Oct 21 09:00:21 web01 sshd[2008]: Accepted password for alice from 203.0.113.77 port 52022 ssh2
Oct 21 09:00:22 web01 sshd[2008]: pam_unix(sshd:session): session opened for user alice(uid=1001) by (uid=0)
Oct 21 09:02:30 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
""",
        },
        "expected": {
            "event_count": 6,
            "expected_timeline": [
                {"ts_utc": "2026-10-21T09:00:01Z", "action": "ssh_login"},
                {"ts_utc": "2026-10-21T09:00:03Z", "action": "ssh_login"},
                {"ts_utc": "2026-10-21T09:00:08Z", "action": "ssh_max_auth_exceeded"},
                {"ts_utc": "2026-10-21T09:00:21Z", "action": "ssh_login"},
                {"ts_utc": "2026-10-21T09:00:22Z", "action": "session_opened"},
                {"ts_utc": "2026-10-21T09:02:30Z", "action": "sudo_command"},
            ],
            "ordered_actions": ["ssh_login", "ssh_login", "ssh_max_auth_exceeded", "ssh_login", "session_opened", "sudo_command"],
            "action_counts": {"ssh_login": 3, "ssh_max_auth_exceeded": 1, "session_opened": 1, "sudo_command": 1},
            "must_include": ["203.0.113.77", "alice", "/etc/shadow"],
        },
    },
    "02-web-exploit-to-server-access": {
        "title": "Web exploit indicators followed by server access",
        "description": "Suspicious upload and shell-like web requests precede SSH access and privileged commands from the same external address.",
        "host": "web01",
        "logs": {
            "access.log": """203.0.113.88 - - [21/Oct/2026:11:02:01 +0000] \"GET /wp-login.php HTTP/1.1\" 404 196 \"-\" \"curl/8.5.0\"
203.0.113.88 - - [21/Oct/2026:11:02:05 +0000] \"POST /upload.php HTTP/1.1\" 200 54 \"http://web01/upload\" \"curl/8.5.0\"
203.0.113.88 - - [21/Oct/2026:11:02:07 +0000] \"GET /uploads/shell.php?cmd=id HTTP/1.1\" 200 61 \"-\" \"curl/8.5.0\"
203.0.113.88 - - [21/Oct/2026:11:02:12 +0000] \"GET /admin/ HTTP/1.1\" 403 381 \"-\" \"curl/8.5.0\"
""",
            "auth.log": """Oct 21 11:03:20 web01 sshd[3100]: Accepted password for deploy from 203.0.113.88 port 53888 ssh2
Oct 21 11:03:21 web01 sshd[3100]: pam_unix(sshd:session): session opened for user deploy(uid=1100) by (uid=0)
Oct 21 11:04:05 web01 sudo:    deploy : TTY=pts/1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/id
Oct 21 11:04:10 web01 sudo:    deploy : TTY=pts/1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
""",
        },
        "expected": {
            "event_count": 8,
            "expected_timeline": [
                {"ts_utc": "2026-10-21T11:02:01Z", "action": "http_request"},
                {"ts_utc": "2026-10-21T11:02:05Z", "action": "http_request"},
                {"ts_utc": "2026-10-21T11:02:07Z", "action": "http_request"},
                {"ts_utc": "2026-10-21T11:02:12Z", "action": "http_request"},
                {"ts_utc": "2026-10-21T11:03:20Z", "action": "ssh_login"},
                {"ts_utc": "2026-10-21T11:03:21Z", "action": "session_opened"},
                {"ts_utc": "2026-10-21T11:04:05Z", "action": "sudo_command"},
                {"ts_utc": "2026-10-21T11:04:10Z", "action": "sudo_command"},
            ],
            "ordered_actions": ["http_request", "http_request", "http_request", "http_request", "ssh_login", "session_opened", "sudo_command", "sudo_command"],
            "action_counts": {"http_request": 4, "ssh_login": 1, "session_opened": 1, "sudo_command": 2},
            "must_include": ["/upload.php", "/uploads/shell.php", "203.0.113.88", "/etc/shadow"],
            "http_statuses": [404, 200, 200, 403],
        },
    },
    "03-account-persistence": {
        "title": "Suspicious account creation and scheduled persistence",
        "description": "A remote login is followed by privilege use, creation of a backdoor account, a group change, and a suspicious cron command.",
        "host": "api01",
        "logs": {
            "auth.log": """Oct 21 12:00:01 api01 sshd[4200]: Accepted publickey for analyst from 198.51.100.55 port 44200 ssh2
Oct 21 12:00:02 api01 sshd[4200]: pam_unix(sshd:session): session opened for user analyst(uid=1200) by (uid=0)
Oct 21 12:03:05 api01 sudo:    analyst : TTY=pts/2 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/sbin/useradd backdoor
Oct 21 12:03:06 api01 useradd[4210]: new user: name=backdoor, UID=1201, GID=1201, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/2
Oct 21 12:04:10 api01 usermod[4220]: add 'backdoor' to group 'sudo'
Oct 21 12:05:00 api01 CRON[4230]: (root) CMD (/tmp/.hidden/reconnect.sh)
""",
        },
        "expected": {
            "event_count": 6,
            "expected_timeline": [
                {"ts_utc": "2026-10-21T12:00:01Z", "action": "ssh_login"},
                {"ts_utc": "2026-10-21T12:00:02Z", "action": "session_opened"},
                {"ts_utc": "2026-10-21T12:03:05Z", "action": "sudo_command"},
                {"ts_utc": "2026-10-21T12:03:06Z", "action": "user_created"},
                {"ts_utc": "2026-10-21T12:04:10Z", "action": "user_group_added"},
                {"ts_utc": "2026-10-21T12:05:00Z", "action": "cron_command"},
            ],
            "ordered_actions": ["ssh_login", "session_opened", "sudo_command", "user_created", "user_group_added", "cron_command"],
            "action_counts": {"ssh_login": 1, "session_opened": 1, "sudo_command": 1, "user_created": 1, "user_group_added": 1, "cron_command": 1},
            "must_include": ["198.51.100.55", "backdoor", "reconnect.sh"],
        },
    },
}


def _remove_readonly(func: Any, path: str, _exc: Any) -> None:
    """Allow rerunning the demo generator when a previous evidence copy is read-only."""
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    func(path)


def create_demo_cases(
    output_dir: str | Path,
    scenario_ids: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Run all synthetic scenarios, or a selected subset, in an isolated output folder.

    Each selected scenario is deterministic and independent. The elapsed time covers
    synthetic input preparation, evidence collection/hash, and normalized timeline
    construction; validation checks are evaluated after timing stops.
    """
    if scenario_ids is None:
        selected_ids = list(SCENARIOS)
    else:
        selected_ids = list(dict.fromkeys(scenario_ids))
        if not selected_ids:
            raise ValueError("at least one scenario_id must be selected")
        unknown = [scenario_id for scenario_id in selected_ids if scenario_id not in SCENARIOS]
        if unknown:
            raise ValueError(f"unknown scenario_id: {unknown[0]}")
    root = Path(output_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "product": "ORISECT",
        "description": "Deterministic synthetic incidents for demos and regression tests.",
        "important": "All log content and timestamps are synthetic. Do not treat these records as real forensic evidence.",
        "scenarios": [],
    }
    results: list[dict[str, Any]] = []

    for scenario_id in selected_ids:
        spec = SCENARIOS[scenario_id]
        # Measures the synthetic evidence-to-timeline workflow, not analyst triage time.
        scenario_started = time.perf_counter()
        scenario_dir = root / scenario_id
        inputs_dir = scenario_dir / "inputs"
        case_dir = scenario_dir / "case"
        inputs_dir.mkdir(parents=True, exist_ok=True)
        # This is a generated demo output path; reset it so repeated runs are idempotent.
        if case_dir.exists():
            shutil.rmtree(case_dir, onerror=_remove_readonly)
        expected = dict(spec["expected"])
        expected_doc = {
            "scenario_id": scenario_id,
            "title": spec["title"],
            "description": spec["description"],
            "synthetic_data": True,
            **expected,
        }
        (scenario_dir / "expected.json").write_text(json.dumps(expected_doc, indent=2) + "\n", encoding="utf-8")
        case = Case.open(case_dir, create=True)
        metadata = case.load_meta()
        metadata["case_id"] = scenario_id
        case.save_meta(metadata)

        # Replace only the synthetic demo case created by this runner; normal user cases are not touched.
        for name, content in spec["logs"].items():
            input_path = inputs_dir / name
            input_path.write_text(content.strip() + "\n", encoding="utf-8")
            source_type = "auth" if name == "auth.log" else "access"
            collect(case, input_path, source_type, tz="UTC", host=spec["host"], year=2026,
                    actor="tracefuse-synthetic-demo", note="Synthetic demonstration input; not real evidence.",
                    allow_duplicate=True)

        build = build_timeline(case, actor="tracefuse-synthetic-demo")
        tracefuse_elapsed_ms = (time.perf_counter() - scenario_started) * 1000.0
        event_dicts = [event.to_dict() for event in build.events]
        actions = [event.action for event in build.events]
        actual_timeline = [{"ts_utc": event.to_dict()["ts_utc"], "action": event.action} for event in build.events]
        counts: dict[str, int] = {}
        for action in actions:
            counts[action] = counts.get(action, 0) + 1
        all_text = "\n".join(event.raw_line for event in build.events)
        missing_indicators = [phrase for phrase in expected.get("must_include", []) if phrase not in all_text]
        statuses = [event.extra.get("status") for event in build.events if event.action == "http_request"]
        checks: dict[str, dict[str, Any]] = {
            "event_count": {
                "passed": len(event_dicts) == expected["event_count"],
                "expected": expected["event_count"], "actual": len(event_dicts),
            },
            "action_sequence": {
                "passed": actions == expected["ordered_actions"],
                "expected": expected["ordered_actions"], "actual": actions,
            },
            "action_counts": {
                "passed": counts == expected["action_counts"],
                "expected": expected["action_counts"], "actual": counts,
            },
            "expected_timeline": {
                "passed": actual_timeline == expected["expected_timeline"],
                "expected_events": len(expected["expected_timeline"]),
                "matching": actual_timeline == expected["expected_timeline"],
            },
            "required_indicators": {
                "passed": not missing_indicators,
                "expected_count": len(expected.get("must_include", [])),
                "missing": missing_indicators,
            },
        }
        if "http_statuses" in expected:
            checks["http_statuses"] = {
                "passed": statuses == expected["http_statuses"],
                "expected": expected["http_statuses"], "actual": statuses,
            }
        integrity_ok = verify(case, record=False).ok
        checks["evidence_integrity"] = {"passed": integrity_ok}
        passed = all(check_result["passed"] for check_result in checks.values())

        check = {
            "scenario_id": scenario_id,
            "title": spec["title"],
            "description": spec["description"],
            "host": spec["host"],
            "input_files": list(spec["logs"]),
            "source_count": len(spec["logs"]),
            "expected_event_count": expected["event_count"],
            "case_path": str(case_dir),
            "inputs_path": str(inputs_dir),
            "event_count": len(event_dicts),
            "gap_count": build.summary["gaps"],
            "tracefuse_elapsed_ms": round(tracefuse_elapsed_ms, 3),
            "actual_action_counts": counts,
            "expected_action_counts": expected["action_counts"],
            "actual_timeline": actual_timeline,
            "expected_timeline": expected["expected_timeline"],
            "checks": checks,
            "passed": bool(passed),
            "integrity_ok": integrity_ok,
        }
        (scenario_dir / "run-result.json").write_text(json.dumps(check, indent=2) + "\n", encoding="utf-8")
        results.append(check)
        manifest["scenarios"].append({"scenario_id": scenario_id, "title": spec["title"], "case_path": f"{scenario_id}/case", "inputs_path": f"{scenario_id}/inputs", "expected_path": f"{scenario_id}/expected.json", "run_result_path": f"{scenario_id}/run-result.json", "passed": check["passed"]})

    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return results
