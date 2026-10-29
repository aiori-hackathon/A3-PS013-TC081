# ORISECT Incident Timeline Dashboard

ORISECT (formerly TRACEFUSE) is our PS-013 hackathon project for reconstructing an incident from system and web logs. The dashboard gives you a simple way to browse the timeline built by the Python engine and check where each event came from.

## What does it show?

- **Findings:** leads raised by fixed, readable rules: repeated failed logins, a login after failures, an address that moves from web requests to SSH across two logs, web-shell requests, admin-path probing, credential files read through sudo, new accounts given admin rights, and cron jobs running from hidden or temporary paths. Each finding states the rule that fired, the MITRE ATT&CK technique it resembles, and the exact `source:line` of every event behind it. **Show evidence** narrows the timeline to those lines.
- **Timeline:** events sorted by normalized UTC time, with the action, outcome, source, and other fields found in the log. A dot next to the action means the event is part of a finding.
- **Who and where:** the most active addresses and accounts, with event and failure counts. Anything seen in more than one source is marked, because that is where separate logs connect. Click one to search for it.
- **Chain of custody:** every custody record (collect, verify, parse, skew changes) with its own hash and its link to the record before it, each checked live.
- **Case summary:** number of events and evidence files, unparsed lines, and the time range covered by the events. If some lines could not be parsed, click the count to see them with the reason. They are kept, never silently dropped.
- **Evidence sources:** source filenames and their SHA-256 hashes, with a copy button.
- **Original log lines:** open an event's source line to see what was actually recorded. ORISECT checks the source hash and custody chain before showing it.
- **Exports:** download the current results as JSON (including the findings, or only one finding's evidence while it is selected) or as a PDF report of the filtered timeline and evidence sources.

The dashboard helps you review a sequence of events; it does not automatically prove that an attack happened or that one event caused another. Findings are leads to check, not conclusions. A successful hash check means the collected evidence matches its recorded hash, not that the original log was complete or genuine.

## Run it locally

You need Python 3.11 or later. From the project root, install the project and its dependencies:

```bash
python -m venv .venv
```

On Windows, activate it with:

```powershell
.venv\Scripts\Activate.ps1
```

On macOS/Linux, use:

```bash
source .venv/bin/activate
```

Then install the requirements and project:

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
```

Start the web app:

```bash
incident-timeline app
```

Then choose **Add evidence** and upload your logs, or the sample evidence in [`demo-evidence/`](demo-evidence/README.md): three logs from one simulated intrusion, with a step-by-step walkthrough.

To open a case you built on the command line instead, pass its folder to `serve`, for example `incident-timeline serve cases/web01`. A folder that contains several cases opens all of them, with a case picker in the top bar.

Open the local URL printed in the terminal (usually `http://127.0.0.1:8765`). Keep the terminal open while using the dashboard; press **Ctrl+C** to stop it.

## Using the dashboard

Start with **Findings**. Choose **Show evidence** on a finding to narrow the timeline to its evidence; **Show all events** returns to the full timeline. Timeline events cited by a finding carry a severity marker.

Use the search box to look for a user, IP address, action, message, path, or hash (press `/` to jump to it, `Esc` to clear it). You can also filter by source, action, outcome, or time range. Filters apply as you change them and can be combined; **Clear filters** resets them, and **Refresh** reloads the case. Use the Previous/Next buttons to move through the results.

Select an event to open it in the **Event** panel: its normalized UTC time next to the timestamp as recorded, the source time zone and clock offset, the parsed fields, the findings that cite it, and the original log line. ORISECT re-hashes the source file before showing that line; if the check fails, the line is not shown. Use **↑**/**↓** to move between events and **Esc** to close the panel (on smaller screens the panel opens as a sheet with Previous/Next buttons). Keep the full case folder if you need to investigate a warning.

**Export JSON** is useful for scripts or further analysis. **Export PDF report** creates a readable report for a handover. Both exports use the active filters, including a finding's evidence, so clear them first if you need the full timeline.

## Sample evidence

[`demo-evidence/`](demo-evidence/README.md) holds an nginx proxy's access logs (one rotated and gzipped) and an application server's `auth.log` from one simulated intrusion. Its README is a ten-minute walkthrough covering:
- upload and hashing;
- time-zone and year handling;
- all the finding rules;
- the event inspector;
- a deliberate 187-second clock fault that is found and corrected;
- exports and tamper detection.

The `incident-timeline demo` command and the **Engine lab** remain as the engine's validation suite. They generate three synthetic cases and check the output against expected results; they are not investigations to present.

## Using your own logs

Collect logs into a case first, then verify and parse them before opening the dashboard. For example:

```bash
incident-timeline collect cases/my-case auth.log --type auth --tz Asia/Kolkata --host server01
incident-timeline collect cases/my-case access.log --type nginx --host web01
incident-timeline verify cases/my-case
incident-timeline parse cases/my-case
incident-timeline serve cases/my-case
```

Use the correct source type and time zone for each log. If some lines are not recognized, check `normalised/gaps.jsonl`; they will not appear as timeline events. More details on the engine commands are in [`src/README.md`](src/README.md).

## Tests and notes

Run the tests from the project root with:

```bash
python -m pytest -q
```

The dashboard is intended for local use and binds to `127.0.0.1` by default. Avoid exposing it to an untrusted network. Keep exported reports with the original case records: a PDF or JSON file is not a replacement for the evidence and custody log.
