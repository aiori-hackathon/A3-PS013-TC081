# Sample evidence: web01 intrusion (simulated)

Four logs from one simulated intrusion, for walking through ORISECT from start to finish:
- preserving evidence;
- normalizing time;
- teaching ORISECT a log format it doesn't know;
- reading findings;
- correcting a clock;
- exporting a report.

**Everything here is simulated.** No real system or person is involved. Addresses come from the ranges reserved for documentation: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and private `10.0.0.0/8`.

## What's in the folder

| File | Host | Format | Time basis | Lines | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `edge01/access.log.1.gz` | edge01 (nginx reverse proxy) | Nginx combined, gzip-rotated | UTC offset in every line; **clock runs 187 s fast** | 89 | `c519438b…eff4b011` |
| `edge01/access.log` | edge01 | Nginx combined | same as above | 84 | `971599c0…77e337c8` |
| `fw01/fw01-traffic.log` | fw01 (perimeter firewall) | FortiGate-style `key=value` traffic log: **no built-in parser** | Local time with its offset (`tz="+0530"`) in every line; clock correct (NTP) | 71 | `991cd526…74368035` |
| `web01/auth.log` | web01 (application server) | Classic syslog (`auth.log`) | Local time, **Asia/Kolkata (UTC+05:30)**, **no year** | 84 | `b047161b…584c7267`* |

\* The full hashes are in [`SHA256SUMS`](SHA256SUMS). Check them before you start:

```bash
cd demo-evidence && shasum -a 256 -c SHA256SUMS
```

(On Linux, `sha256sum -c SHA256SUMS` works too.) The repository marks this folder as binary, so the bytes, and therefore the hashes, are identical on every OS.

### What happened (presenter's notes)

All times are real UTC.

| When | Where | What |
| --- | --- | --- |
| Oct 24, 16:12 | edge01 | `203.0.113.45` probes the shop: `/wp-login.php`, `/.env`, `/.git/config`, `/admin`, `/phpmyadmin/`. It finds the avatar upload page. |
| Oct 25, 08:31:52 | edge01 | Uploads `avatar_7731.php` through `/upload.php`. |
| 08:32:06–08:33:02 | edge01 | Runs `id`, `ls -la ..` and `cat ../config.php` through it. The config file holds the `deploy` password. |
| 08:34:11–08:34:22 | web01 | Two failed SSH logins as `root`, one as the invalid user `admin`. |
| 08:34:28 | web01 | **Logs in as `deploy`** with the stolen password. |
| 08:35:40 | web01 | `sudo cat /etc/shadow` |
| 08:36:30–08:36:52 | web01 | Creates `svc-backup` and adds it to `sudo` (a backdoor admin account). |
| 08:37:40 | web01 | Installs a cron job for `svc-backup` from `/tmp/.cache/`. |
| 08:40:01, 08:45:01 | web01 → 203.0.113.45 | Cron runs `/tmp/.cache/upd.sh`, which calls the attacker's server (about 400 bytes each time). |
| **08:41:12–08:44:30** | **web01 → 203.0.113.45** | **Uploads 48.2 MB to the attacker over HTTPS, in three connections. Only the firewall log shows this.** |
| 08:46:10 | web01 | The attacker disconnects. |
| 08:47:30 | edge01 | Deletes the web shell through itself. |

Background activity:
- shop visitors;
- a monitoring server (`10.0.4.20`) that checks edge01 over HTTP and web01's SSH port at the same instant every five minutes;
- hourly cron jobs;
- an administrator (`alice`) running `apt-get update`;
- web01's hourly NTP traffic;
- internet scanners blocked by the firewall.

**Built-in traps, each demonstrating a feature:**
- **Unknown format.** ORISECT has no parser for the firewall log. Every line is kept as an unparsed line until the analyst teaches ORISECT the format, and only then does the data theft appear.
- **Clock skew.** edge01's clock runs 187 s fast. Uncorrected, the attacker seems to log in as `deploy` before reading the file that held the password. The firewall, whose clock is right, recorded the same web requests three minutes earlier than edge01 did.
- **Time zone.** `auth.log` is in Indian local time. Forget to set the zone and every web01 event is off by 5 h 30 min.
- **Missing year.** Classic syslog lines have no year. ORISECT infers it and flags every affected event.
- **Rotated, compressed log.** The previous day's access log is a `.gz` file, read transparently.
- **Damaged lines.** `auth.log` has a run of NUL bytes and a truncated line. Both are kept as unparsed lines with a reason, never dropped.

---

## Walkthrough in the web app (about 12 minutes)

### 0. Start

From the repository root:

```bash
python -m pip install -r requirements.txt
```

```bash
python -m pip install -e .
```

```bash
incident-timeline app
```

Open the address it prints (usually http://127.0.0.1:8765). Note the **Case storage** path it prints; you'll need it in step 9.

### 1. Preserve the evidence

1. Choose **Add evidence**, and name the investigation, for example `web01 intrusion`.
2. Choose **Choose a folder** and select this `demo-evidence` folder (or drag the folder onto the drop zone).
3. ORISECT reads the first lines of each file and picks its format; the hint under **Log format** says what it found. Check the settings:

   | File | Log format | Source time zone | Host |
   | --- | --- | --- | --- |
   | `access.log` | Web access log (Nginx / Apache) | `UTC` | `edge01` |
   | `access.log.1.gz` | Web access log (Nginx / Apache) | `UTC` | `edge01` |
   | `fw01-traffic.log` | **Other format (teach ORISECT after upload)** | `UTC` (its lines carry their own offset) | `fw01` |
   | `auth.log` | Linux authentication / syslog | **`Asia/Kolkata`** | `web01` |

4. Choose **Preserve and build timeline**.

**Talking point:** each file is copied into a case folder, made read-only and hashed with SHA-256, and a custody record is written, all *before* anything is parsed. Compare the hashes in **Case context → Evidence sources** with `SHA256SUMS`. The firewall log is preserved and hashed like the others, even though ORISECT can't read it yet.

> **Optional trap:** run the upload once with `auth.log` left at `UTC`. Every web01 event lands 5 h 30 min late, and the Timeline Confidence Lab counts them under *Time zone assumed*. Then redo it correctly.

### 2. Read the case header

You should see:
- **255 events**, **4 evidence sources** and **73 unparsed lines**;
- a time window of 24 Oct–25 Oct 2026;
- **Evidence integrity verified**.

Choose **View** next to *Unparsed lines*. Two kinds of lines are listed:
- **Lines 14 and 43 of `auth.log`:** the NUL run and the truncated `Oct 25 13:5`, each listed with the reason it couldn't be parsed. They stay in the evidence; they just aren't events.
- **All 71 lines of `fw01-traffic.log`.** ORISECT has no built-in parser for this firewall's format.

### 3. Teach ORISECT the firewall's format

1. Next to `fw01-traffic.log` (under **Unparsed lines**, or in **Evidence sources**), choose **Teach this format**.
2. The rule assistant reads the 71 lines and explains what it found:
   - the time is split across the `date` and `time` keys;
   - the `tz` key gives each line's UTC offset, so no time zone has to be assumed;
   - `action` gives the outcome: `accept` and `close` mean success, `deny` means failure;
   - `srcip`, `dstip` and `sentbyte` become source address, destination address and bytes sent, and other keys are mapped where their names are well known.
3. It has already tested the rule. **Would become events: 71 of 71.** Read the example rows: `21:42:09 +0530` in the log became `16:12:09 UTC`.
4. Everything is editable: rename the rule (for example `fw01 traffic log`), change a mapping, and choose **Test on unparsed lines** again. **Rule as JSON** shows exactly what will be approved.
5. Enter your name under **Approved by** and choose **Approve and rebuild timeline**.

The page reports: *R001 approved … The timeline was rebuilt: 326 events (+71), 2 unparsed lines (−71). 1 finding added.*

**Talking points:**
- The suggestion is **deterministic**. ORISECT read the structure of the lines; it didn't guess with a language model, and the same lines always give the same proposal.
- An approved rule is plain data: key=value extraction plus a field mapping, applied identically on every rebuild.
- The approval is **evidence handling**. **Chain of custody** gains an `approve_parser_rule` record (R001) holding the rule and its SHA-256, followed by a `parse` record that lists the rules it applied. Edit the rule inside the custody log and the chain breaks, and ORISECT stops applying the rule.
- **Case context → Parser rules** shows who approved R001 and when. **Revoke** turns its events back into unparsed lines, and that is recorded too.

### 4. Findings

Before any clock correction there are **12 findings**:

| Severity | Finding | ATT&CK |
| --- | --- | --- |
| High | Login as deploy after failed attempts | T1078 |
| High | Possible web shell used from 203.0.113.45 | T1505.003 |
| High | deploy accessed a credential file through sudo | T1003.008 |
| High | New account svc-backup given admin rights | T1136.001 |
| High | Cron job runs from a hidden or temporary path (×2, one per run) | T1053.003 |
| High | **Large upload from 10.0.2.11 to 203.0.113.45** (new, from the firewall) | T1048 |
| Medium | Probing of admin and login paths from 203.0.113.45 | T1595 |
| Medium | Repeated failed logins from 203.0.113.45 | T1110 |
| Info | Some timestamps are partly assumed (year inferred for auth.log) | – |
| Info | alice ran 1 command through sudo | T1548.003 |
| Info | deploy ran 3 commands through sudo | T1548.003 |

Read the new one: *48.2 MB sent from 10.0.2.11 to 203.0.113.45 in 3 connections in 2 min. Its other 21 outbound connections in this evidence sent 5.2 KB in total. 203.0.113.45 also appears in access.log, access.log.1.gz, auth.log.* The theft was in the evidence from the start, in a format nobody had read.

On **Possible web shell used from 203.0.113.45**, choose **Show evidence**. The timeline narrows to the upload and the four shell requests, and **Export JSON** and **PDF report** now cover only those lines.

**Talking point:** every finding names its rule and cites exact `source:line` references. They are leads to verify, not conclusions.

### 5. Inspect an event

Select the `cat ../config.php` request. The **Event** panel shows:
- the normalized UTC time next to the timestamp as recorded (`25/Oct/2026:08:36:09 +0000`);
- the parsed fields (method, path, status, user agent), labelled *derived, not original*;
- the original log line, shown only after ORISECT re-hashes `access.log` and confirms it matches.

Select a firewall event: its fields include `parser_rule: R001`, so every event says which approved rule read it.

Use **↑** and **↓** to move between events, and **Esc** to close the panel.

### 6. Pivot on the attacker

Choose **Show all events**. Under **Case context → Who and where**, `203.0.113.45` is marked *Seen in 4 sources*. Select it: the timeline filters to the **37 events** that mention it across all four logs, including the firewall's records of the upload.

### 7. Spot the contradiction

Read those events in order:
1. The attacker **logs in as `deploy` at 08:34:28**.
2. Then the upload appears in edge01's log at 08:34:59.
3. Then `cat ../config.php` at 08:36:09.

How could the attacker use the password before stealing it? The order is wrong, which points to a clock problem rather than an impossible attack.

There's a second witness. The firewall recorded the attacker's HTTPS sessions to edge01 closing at 08:31:53, 08:32:07, 08:32:32 and 08:33:03, three minutes *before* edge01's own timestamps. Two independent clocks disagree, and the firewall agrees with web01.

### 8. Test the clock in the Timeline Confidence Lab

1. In **Clock-offset preview**, choose the `access.log` source.
2. Enter **187** seconds and choose **Preview shift**.
3. The preview recalculates 84 events, moves **144 records** in the merged order and finds **17 exact cross-source ties**.

Open **Exact cross-source timestamp ties**:
- Most ties are the monitoring server's HTTP check on edge01 and its SSH check on web01, now on the same second. That's evidence the offset is right.
- Others pair the firewall's records of the attacker's SSH sessions with web01's own lines for them.

Nothing has been saved; the preview never changes the case. Choose **Discard preview**.

### 9. Correct the clock for real (command line)

In a second terminal, use the case folder: the **Case storage** path from step 0, plus the `CASE-…` ID in the browser's address bar. Use the source ID that **Evidence sources** shows for `auth.log` as the trusted reference.

Estimate first; this is a dry run:

```bash
incident-timeline skew cases/web-app/CASE-xxxxxxxxxxxx --reference S004
```

Expect `clock +187.000s (ahead), 22 matches` for both access logs, and `+0.000s (in step), 5 matches` for the firewall. The estimate pairs events that share a client address, and the monitoring server's simultaneous checks agree to the second.

Store it, then rebuild the timeline:

```bash
incident-timeline skew cases/web-app/CASE-xxxxxxxxxxxx --reference S004 --apply
```

```bash
incident-timeline parse cases/web-app/CASE-xxxxxxxxxxxx
```

Back in the browser, choose **Refresh**. Now:
- `cat ../config.php` (08:33:02) comes **before** the `deploy` login (08:34:28), and edge01's web-shell requests line up with the firewall's records of them;
- a **13th finding** appears: **203.0.113.45 moved from web requests to SSH** (T1021.004). It was hidden because, on edge01's fast clock, every web request that day seemed to come after the SSH login;
- **Chain of custody** lists three new `set_skew` records with the method and match counts, so the correction itself is evidence. The firewall's says its clock was in step.

### 10. Export

- **PDF report:** opens with the findings, each with the `source:line` and file SHA-256 of every line behind it, and the original text of those lines. Then the evidence sources with full hashes, and the filtered timeline.
- **Export JSON:** events plus findings, each finding with its evidence references, for scripts or other tools.
- With a finding selected (**Show evidence**), both exports cover only that finding's evidence.

### 11. Optional: show tamper detection

Do this on a copy of the case, never the one you'll present:

```bash
cp -r cases/web-app/CASE-xxxxxxxxxxxx /tmp/tamper-demo && chmod u+w /tmp/tamper-demo/evidence/*auth.log && echo "forged" >> /tmp/tamper-demo/evidence/*auth.log
```

```bash
incident-timeline serve /tmp/tamper-demo
```

The header shows **Integrity check failed**, and the Event panel refuses to show original lines from the altered file.

---

## Walkthrough on the command line

The same investigation without the browser:

```bash
incident-timeline collect cases/web01 demo-evidence/edge01/access.log.1.gz --type nginx --host edge01
incident-timeline collect cases/web01 demo-evidence/edge01/access.log --type nginx --host edge01
incident-timeline collect cases/web01 demo-evidence/web01/auth.log --type auth --tz Asia/Kolkata --year 2026
incident-timeline collect cases/web01 demo-evidence/fw01/fw01-traffic.log --type other --host fw01
incident-timeline verify cases/web01
incident-timeline parse cases/web01
incident-timeline rules suggest cases/web01 --source S004 --out fw01-rule.json
incident-timeline rules approve cases/web01 fw01-rule.json
incident-timeline parse cases/web01
incident-timeline skew cases/web01 --reference S003
incident-timeline skew cases/web01 --reference S003 --apply
incident-timeline parse cases/web01
incident-timeline serve cases/web01
```

Notes on these commands:
- `--type other` stores a log ORISECT has no parser for: all its lines are kept as unparsed lines.
- `rules suggest` proposes a rule from those lines and tests it. It writes the rule to `fw01-rule.json`, so you can read and edit it before `rules approve` records it in the custody log.
- `rules list` shows approved rules, and `rules revoke` withdraws one.
- `--year 2026` pins the year for `auth.log`. The web upload doesn't ask for one, so there the year is inferred from the upload date and flagged. That's correct until late October 2027.

## Expected results at a glance

| | After upload | After teaching the firewall format | After clock correction |
| --- | --- | --- | --- |
| Events | 255 | 326 | 326 |
| Unparsed lines | 73 (71 firewall, `auth.log` lines 14 and 43) | 2 | 2 |
| Findings (web app) | 11 | 12 (+ large upload to 203.0.113.45) | 13 (+ web → SSH pivot) |
| `cat ../config.php` vs `deploy` login | 08:36:09, **after** the login | unchanged | 08:33:02, **before** the login |
| Skew estimate | – | edge01 sources +187 s (22 matches each), fw01 +0 s (5 matches) | applied |

On the command line, `--year` removes the *partly assumed* finding, so the counts are one lower: 10, 11 and 12.
