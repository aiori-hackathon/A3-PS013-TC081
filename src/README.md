# Core engine: `incident_timeline`

Turns raw log files into hashed evidence and a merged, line-traceable UTC timeline.
Python 3.11+, standard library only (plus `tzdata` on Windows). Works offline.

| Module | Does |
|---|---|
| `evidence.py` | Copies each log into a case's evidence store, takes its SHA-256, makes the copy read-only and writes a hash-chained custody record. `verify` re-hashes everything. |
| `parsers/syslog.py` | auth.log / syslog: classic RFC 3164 (no year, no zone), ISO / rsyslog, RFC 5424. Picks out sshd, PAM, sudo, su, cron and account-change events. |
| `parsers/access.py` | Apache / Nginx Common and Combined Log Format (also vhost prefixes and extra trailing fields). |
| `timeutil.py` | Zone handling (IANA names or fixed offsets), daylight-saving ambiguity, RFC 3339 output. |
| `skew.py` | Clock-skew estimation between two sources, automatic or from an analyst-chosen pair of lines. |
| `pipeline.py` | Checks hashes, parses the evidence copies, applies skew, merges and writes the outputs. |
| `cli.py` | Command-line interface. |

## Setup

```sh
pip install -r requirements.txt
```

Run commands from the repository root with `PYTHONPATH=src` (or `pip install -e .`, which adds an
`incident-timeline` command).

## Usage

```sh
export PYTHONPATH=src            # Windows PowerShell: $env:PYTHONPATH="src"

# 1. Collect: copy, hash and lock each log; record custody
python -m incident_timeline collect cases/c1 /var/log/auth.log   --type auth   --tz Asia/Kolkata
python -m incident_timeline collect cases/c1 access.log          --type nginx  --host web01
python -m incident_timeline sources cases/c1

# 2. Verify: re-hash evidence and check the custody chain (exit code 1 on failure)
python -m incident_timeline verify cases/c1

# 3. Skew (optional): compare clocks against a trusted source
python -m incident_timeline skew cases/c1 --reference S001                  # estimate (dry run)
python -m incident_timeline skew cases/c1 --reference S001 --apply          # store usable offsets
python -m incident_timeline skew cases/c1 --anchor S002:120=S001:45 --apply # same event in both
python -m incident_timeline skew cases/c1 --set S002=-30                    # by hand

# 4. Parse: build the timeline
python -m incident_timeline parse cases/c1
```

`--tz` is the zone the host writes its local times in. It matters for logs whose lines carry no
offset (classic syslog). Without it, UTC is assumed and every affected event is flagged
`tz_assumed`. `--year` sets the first line's year when the file's modification time cannot be
trusted. Every command accepts `--actor NAME` for the custody log (default: `user@host`).

## Case directory

```
cases/c1/
  case.json                 sources and their settings (zone, host, year, skew offset)
  custody.jsonl             who / when / what / SHA-256 for every collect, verify, set_skew, parse
  evidence/S001_auth.log    read-only copies; these are what get parsed, never the originals
  normalised/events.jsonl   one event per parsed line, sorted by corrected UTC time
  normalised/gaps.jsonl     every line that was not understood, with the reason
  normalised/summary.json   per-source counts, time range, zones, skew, parse ratio, notes
```

Each custody record carries the SHA-256 of the record before it. If any record is edited or
removed, `verify` reports the break. Expected evidence hashes are read from the custody log, not
from `case.json`.

`parse` refuses to run if any evidence copy no longer matches its collection hash
(`--force` overrides this).

## `events.jsonl` record (contract for the viewer and report)

```json
{
  "event_id": "S001:4",
  "ts_utc": "2026-12-31T18:30:12Z",
  "ts_raw": "Jan  1 00:00:12",
  "source_id": "S001", "source_type": "syslog", "source_file": "auth.log",
  "file_sha256": "f9a68d41…", "line_no": 4,
  "raw_line": "Jan  1 00:00:12 web01 sshd[1205]: Accepted password for alice from 203.0.113.7 port 51040 ssh2",
  "host": "web01", "process": "sshd", "pid": 1205,
  "user": "alice", "src_ip": "203.0.113.7",
  "action": "ssh_login", "outcome": "success",
  "message": "Accepted password for alice from 203.0.113.7 port 51040 ssh2",
  "tz": "Asia/Kolkata", "tz_assumed": false, "year_inferred": true,
  "skew_offset_s": 0.0,
  "extra": {"src_port": 51040, "method": "password"}
}
```

- `ts_utc` is the corrected instant: the source's own reading in UTC minus `skew_offset_s`
  (seconds that source's clock runs ahead of the reference clock).
- `file_sha256` and `line_no` identify the exact evidence line a statement rests on.
- `outcome` is `success`, `failure` or `null`. For access logs, any status of 400 or above is a failure.
- Possible `extra` flags: `dst_ambiguous` (the local time is repeated or skipped by a daylight-saving
  change), `invalid_user`, `request_malformed`.
- `incident_timeline.models.load_events(path)` reads the file back into `Event` objects.

Actions currently recognised: `ssh_login`, `ssh_invalid_user`, `ssh_max_auth_exceeded`,
`ssh_disconnect`, `ssh_connection_closed`, `ssh_connection`, `session_opened`, `session_closed`,
`auth_failure`, `password_changed`, `sudo_command`, `su`, `user_created`, `user_deleted`,
`group_created`, `user_group_added`, `cron_command`, `http_request`.

## How time is normalised

- **Missing year (classic syslog):** the year goes up by one when the month drops sharply
  (Dec → Jan). The starting year is chosen so the last line is no later than the file's
  modification time at collection plus one day. Affected events are marked `year_inferred`.
- **Zones:** an offset written on the line always wins. Otherwise the source's `--tz` is used.
  IANA zones follow daylight-saving rules.
- **Clock skew:** events from two sources that share a key (default: `src_ip`) are paired within a
  window. The tightest cluster of time differences gives the offset (median), with its spread and
  match count reported. Pairs of unrelated events spread out, while the true skew forms a peak.

## Tests

```sh
pytest
```

Sample logs in `src/tests/data/` are marked `-text` in `.gitattributes` so their hashes are the
same on Windows and Linux.
