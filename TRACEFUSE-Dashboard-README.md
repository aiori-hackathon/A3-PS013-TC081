# TRACEFUSE Incident Timeline Dashboard

TRACEFUSE is our PS-013 hackathon project for reconstructing an incident from system and web logs. The dashboard gives you a simple way to browse the timeline built by the Python engine and check where each event came from.

## What does it show?

- **Timeline:** events sorted by normalized UTC time, with the action, outcome, source, and other fields found in the log.
- **Case summary:** number of events and evidence files, unparsed lines, and the time range covered by the events.
- **Evidence sources:** source filenames and their SHA-256 hashes.
- **Original log lines:** open an event's source line to see what was actually recorded. TRACEFUSE checks the source hash and custody chain before showing it.
- **Exports:** download the current results as JSON or a PDF report.

The dashboard helps you review a sequence of events; it does not automatically prove that an attack happened or that one event caused another. A successful hash check means the collected evidence matches its recorded hash, not that the original log was complete or genuine.

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

Generate the demo cases:

```bash
incident-timeline demo --output cases/demo-scenarios
```

The command creates and checks three synthetic cases. To open the first one, run:

```bash
incident-timeline serve cases/demo-scenarios/01-brute-force-to-sudo/case
```

Open the local URL printed in the terminal (usually `http://127.0.0.1:8765`). Keep the terminal open while using the dashboard; press **Ctrl+C** to stop it.

To view another case, stop the server and run `incident-timeline serve` with that case's path.

## Using the dashboard

Use the search box to look for a user, IP address, action, message, path, or hash. You can also filter by source, action, outcome, or time range. Filters can be combined; **Reset** clears them, and **Refresh** reloads the case. Use the Previous/Next buttons to move through the results.

Choose **View original line** on an event to inspect its matching line in the collected evidence. If the integrity check fails, TRACEFUSE will not show that line. Keep the full case folder if you need to investigate a warning.

**Export JSON** is useful for scripts or further analysis. **Export PDF report** creates a readable report for a handover or demo. Both exports use the active filters, so clear them first if you need the full timeline.

## Demo scenarios

The demo command generates these repeatable examples:

1. **Brute force to sudo:** repeated SSH login failures followed by a successful login and privileged activity.
2. **Web exploit to server access:** suspicious web requests followed by server access and privileged commands.
3. **Account persistence:** remote access and administrative actions, including account and cron changes.

These logs are synthetic, not real incident evidence. Each scenario includes expected results so the reconstruction can be checked.

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
