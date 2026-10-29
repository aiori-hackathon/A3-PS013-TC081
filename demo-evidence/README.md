# Sample evidence: web01 intrusion (simulated)

Three logs from one simulated intrusion, for walking through ORISECT from start to finish: preserving evidence, normalizing time, reading findings, correcting a clock, and exporting a report.

**Everything here is simulated.** No real system or person is involved. Addresses come from the ranges reserved for documentation: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and private `10.0.0.0/8`.

## What's in the folder

| File | Host | Format | Time basis | Lines | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `edge01/access.log.1.gz` | edge01 (nginx reverse proxy) | Nginx combined, gzip-rotated | UTC offset in every line; **clock runs 187 s fast** | 89 | `c519438b…eff4b011` |
| `edge01/access.log` | edge01 | Nginx combined | same as above | 84 | `971599c0…77e337c8` |
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
| 08:40:01, 08:45:01 | web01 | Cron runs `/tmp/.cache/upd.sh`. |
| 08:46:10 | web01 | The attacker disconnects. |
| 08:47:30 | edge01 | Deletes the web shell through itself. |

Background activity: shop visitors, a monitoring server (`10.0.4.20`) that checks edge01 over HTTP and web01's SSH port at the same instant every five minutes, hourly cron jobs, and an administrator (`alice`) running `apt-get update`.

**Built-in traps, each demonstrating a feature:**
- **Clock skew.** edge01's clock runs 187 s fast. Uncorrected, the attacker seems to log in as `deploy` before reading the file that held the password.
- **Time zone.** `auth.log` is in Indian local time. Forget to set the zone and every web01 event is off by 5 h 30 min.
- **Missing year.** Classic syslog lines have no year. ORISECT infers it and flags every affected event.
- **Rotated, compressed log.** The previous day's access log is a `.gz` file, read transparently.
- **Damaged lines.** `auth.log` has a run of NUL bytes and a truncated line. Both are kept as unparsed lines with a reason, never dropped.

---

## Walkthrough in the web app (about 10 minutes)

### 0. Start

From the repository root:

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
incident-timeline app
```

Open the address it prints (usually http://127.0.0.1:8765). Note the **Case storage** path it prints; you'll need it in step 8.

### 1. Preserve the evidence

1. Choose **Add evidence**, and name the investigation, for example `web01 intrusion`.
2. Choose **Choose a folder** and select this `demo-evidence` folder (or drag the folder onto the drop zone).
3. Set each source as follows:

   | File | Log format | Source time zone | Host |
   | --- | --- | --- | --- |
   | `access.log` | Web access log (Nginx / Apache) | `UTC` | `edge01` |
   | `access.log.1.gz` | Web access log (Nginx / Apache) | `UTC` | `edge01` |
   | `auth.log` | Linux authentication / syslog | **`Asia/Kolkata`** | `web01` |

4. Choose **Preserve and build timeline**.

**Talking point:** each file is copied into a case folder, made read-only and hashed with SHA-256, and a custody record is written, all *before* anything is parsed. Compare the hashes in **Case context → Evidence sources** with `SHA256SUMS`.

> **Optional trap:** run the upload once with `auth.log` left at `UTC`. Every web01 event lands 5 h 30 min late, and the Timeline Confidence Lab counts them under *Time zone assumed*. Then redo it correctly.

### 2. Read the case header

You should see:
- **255 events**, **3 evidence sources** and **2 unparsed lines**;
- a time window of 24 Oct–25 Oct 2026;
- **Evidence integrity verified**.

Choose **View** next to *Unparsed lines*. Lines 14 and 43 of `auth.log` (the NUL run and the truncated `Oct 25 13:5`) are listed with the reason they couldn't be parsed. They stay in the evidence; they just aren't events.

### 3. Findings

Before any clock correction there are **11 findings**:

| Severity | Finding | ATT&CK |
| --- | --- | --- |
| High | Login as deploy after failed attempts | T1078 |
| High | Possible web shell used from 203.0.113.45 | T1505.003 |
| High | deploy accessed a credential file through sudo | T1003.008 |
| High | New account svc-backup given admin rights | T1136.001 |
| High | Cron job runs from a hidden or temporary path (×2, one per run) | T1053.003 |
| Medium | Probing of admin and login paths from 203.0.113.45 | T1595 |
| Medium | Repeated failed logins from 203.0.113.45 | T1110 |
| Info | Some timestamps are partly assumed (year inferred for auth.log) | – |
| Info | alice ran 1 command through sudo | T1548.003 |
| Info | deploy ran 3 commands through sudo | T1548.003 |

On **Possible web shell used from 203.0.113.45**, choose **Show evidence**. The timeline narrows to the upload and the four shell requests, and **Export JSON** now exports only those lines.

**Talking point:** every finding names its rule and cites exact `source:line` references. They are leads to verify, not conclusions.

### 4. Inspect an event

Select the `cat ../config.php` request. The **Event** panel shows:
- the normalized UTC time next to the timestamp as recorded (`25/Oct/2026:08:36:09 +0000`);
- the parsed fields (method, path, status, user agent), labelled *derived, not original*;
- the original log line, shown only after ORISECT re-hashes `access.log` and confirms it matches.

Use **↑** and **↓** to move between events, and **Esc** to close the panel.

### 5. Pivot on the attacker

Choose **Show all events**. Under **Case context → Who and where**, `203.0.113.45` is marked *Seen in 3 sources*. Select it: the timeline filters to the attacker's **21 events** across both hosts.

### 6. Spot the contradiction

Read those 21 events in order:
1. The attacker **logs in as `deploy` at 08:34:28**.
2. Then the upload appears at 08:34:59.
3. Then `cat ../config.php` at 08:36:09.

How could the attacker use the password before stealing it? The order is wrong, which points to a clock problem rather than an impossible attack.

### 7. Test the clock in the Timeline Confidence Lab

1. In **Clock-offset preview**, choose the `access.log` source.
2. Enter **187** seconds and choose **Preview shift**.
3. The preview recalculates 84 events, moves **121 records** in the merged order and finds **12 exact cross-source ties**.

Open **Exact cross-source timestamp ties**: each tie is the monitoring server's HTTP check on edge01 and its SSH check on web01, now on the same second. That's evidence the offset is right.

Nothing has been saved; the preview never changes the case. Choose **Discard preview**.

### 8. Correct the clock for real (command line)

In a second terminal, use the case folder: the **Case storage** path from step 0, plus the `CASE-…` ID in the browser's address bar. Use the source ID that **Evidence sources** shows for `auth.log` as the trusted reference (usually `S003`).

Estimate first; this is a dry run:

```bash
incident-timeline skew cases/web-app/CASE-xxxxxxxxxxxx --reference S003
```

Expect `clock +187.000s (ahead), 22 matches` for both access logs. The estimate pairs events that share a client address, and the monitoring server's simultaneous checks agree to the second.

Store it, then rebuild the timeline:

```bash
incident-timeline skew cases/web-app/CASE-xxxxxxxxxxxx --reference S003 --apply
```

```bash
incident-timeline parse cases/web-app/CASE-xxxxxxxxxxxx
```

Back in the browser, choose **Refresh**. Now:
- `cat ../config.php` (08:33:02) comes **before** the `deploy` login (08:34:28);
- a **12th finding** appears: **203.0.113.45 moved from web requests to SSH** (T1021.004). It was hidden because, on edge01's fast clock, every web request that day seemed to come after the SSH login;
- **Chain of custody** lists two new `set_skew` records with the method and match counts, so the correction itself is evidence.

### 9. Export

- **PDF report:** the filtered timeline and evidence sources, with SHA-256 hashes, for a handover.
- **Export JSON:** events plus findings, for scripts or other tools. With a finding selected, only its evidence is exported.

### 10. Optional: show tamper detection

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
incident-timeline verify cases/web01
incident-timeline parse cases/web01
incident-timeline skew cases/web01 --reference S003
incident-timeline skew cases/web01 --reference S003 --apply
incident-timeline parse cases/web01
incident-timeline serve cases/web01
```

`--year 2026` pins the year for `auth.log`. The web upload doesn't ask for one, so there the year is inferred from the upload date and flagged. That's correct until late October 2027.

## Expected results at a glance

| | Before clock correction | After |
| --- | --- | --- |
| Events | 255 | 255 |
| Unparsed lines | 2 (auth.log lines 14 and 43) | 2 |
| Findings | 11 | 12 (+ web → SSH pivot) |
| `cat ../config.php` vs `deploy` login | 08:36:09, **after** the login | 08:33:02, **before** the login |
| Skew estimate | edge01 sources +187 s, 22 matches each | applied |
