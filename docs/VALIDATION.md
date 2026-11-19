# Validation record

What is checked, how to repeat it, and what is not claimed. Run everything from the repository root.

## Automated tests

```bash
python -m pip install -r requirements.txt
PYTHONPATH=src python -m pytest -q
```

**113 tests pass** (96 test functions, some parametrised). Node.js is needed for the three browser-engine tests; without it they are skipped.

| Area | File | What is checked |
| --- | --- | --- |
| Evidence and custody | `test_evidence.py` | Byte-for-byte copies, SHA-256, read-only evidence, hash-chained custody, tamper and deletion detection |
| Parsers | `test_syslog.py`, `test_access.py` | RFC 3164 / ISO / RFC 5424 syslog, Apache/Nginx common and combined, gzip, malformed lines kept as gaps |
| Time | `test_timeutil.py`, `test_time_analysis.py` | IANA zones and fixed offsets, DST ambiguity and gaps, inferred years, the Timeline Confidence Lab |
| Clock skew | `test_skew.py`, `test_web.py` | Automatic estimation, anchors, manual offsets; in the web app, edge01's 187 s fast clock found from 22 matching pairs per log, corrected with custody records, revealing the web-to-SSH pivot |
| Parser rules | `test_rules.py` | Rule proposal from unknown lines, dry runs, approval and revocation in custody |
| Findings | `test_findings.py` | Every detection rule, its evidence lines, ATT&CK technique and stage |
| Exports | `test_exports.py`, `test_web.py` | PDF and JSON, filtered and finding-scoped exports, the evidence bundle verified with plain SHA256SUMS and `verify-bundle`, a one-byte change caught twice |
| Web app | `test_web.py` | Upload, duplicate content collected once, failed uploads leave no half-built case, the full sample-evidence walkthrough, security headers and script-hash CSP, cross-site requests refused |
| Hosted deployment | `test_hosted.py` | A case lost by a serverless instance restored from the browser's signed copy, a stale copy refused (409) and replaced, forged or path-escaping archives refused, no case listing |
| Browser engines | `test_frontend_js.py` | Time-zone matching (misspellings, abbreviations, offsets), theme-reveal geometry |
| Scenarios and CLI | `test_scenarios.py`, `test_cli.py` | Three synthetic incidents against their expected timelines; the CLI walkthrough |

## Browser checks

Run in Chromium (Playwright) against the app serving the sample evidence, at 1440 px and 390 px (the app bar also at 820 px), in the dark and light themes:

- every tab of the case page renders with no console errors;
- the time-zone picker suggests `Asia/Kolkata` for `kolkatta`, `America/Los_Angeles` for `pst` (Tab accepts it), and choosing with the mouse keeps the upload window open;
- reloading after the hosted server lost a case, or held an older copy of it, restores it from the browser's copy; PDF export works the same way;
- the theme switch: the reveal grows from the toggle (screenshots at 250, 600, 1000 and 1500 ms), clears its transition state after 2 s, persists across reloads, switches instantly with reduced motion, and five rapid clicks end on the right theme;
- the incident storyline opens a finding's evidence when a step is selected; dragging across the density strip filters the timeline to that window.

## Light theme contrast

Worst-case contrast of each text colour against every light-theme surface (WCAG AA needs 4.5:1):

| Text | Worst ratio |
| --- | ---: |
| Primary text | 15.8:1 |
| Secondary text | 8.7:1 |
| Muted text | 5.3:1 |
| Accent (links, emerald) | 4.5:1 |
| OK / warning / error / info | 4.8 / 5.2 / 5.0 / 5.9:1 |
| White on the primary button | 4.7:1 or more |

## External data

`scripts/benchmark_external.py` runs Elastic's published NGINX sample (pinned by SHA-256) through the web app's own upload path, three fresh investigations per set. See the README for the table; raw results, runtime and per-run values are in [`benchmarks/elastic-nginx-results.json`](benchmarks/elastic-nginx-results.json). All 51,462 lines parse, with no record limit; search stays near 24 ms on the whole file because each case's parsed timeline and search index are reused until the timeline changes.

## PS-013 acceptance

| Requirement | Where |
| --- | --- |
| At least two log formats | Linux auth/syslog and Apache/Nginx access built in; other formats taught with approved parser rules (the sample firewall log) |
| Preserve originals and normalized copies | `evidence/` (byte for byte, read-only, hashed) and `normalised/`; both in the evidence bundle |
| Evidence hashes | SHA-256 at collection, re-verified on every load; hash-chained custody; `SHA256SUMS` in the bundle |
| Time zones and clock skew | Per-source zones with DST and year flags; automatic skew detection with evidence pairs and one-click correction; offset previews in the Timeline Confidence Lab |
| Searchable chronological timeline | Search across events and raw lines, source/action/outcome/time filters, drag-to-filter density strip, paging |
| Document parsing gaps | Every unparsed line kept with its reason; the rule assistant can turn them into events |
| Synthetic scenarios | Three in the Engine Validation Lab (`incident-timeline demo`) plus the four-log sample intrusion |
| Assisted versus manual triage | The Triage time study records paired manual and assisted timings per scenario; no results are claimed until trials are run |
| Incident summary report | PDF opening with the findings and their evidence, JSON export, evidence bundle |

## Not claimed

- No user accounts or access control: anyone with a case's link can open it. The hosted demo keeps cases for up to six hours and is not for real evidence.
- SHA-256 and the custody chain show that evidence is unchanged since collection; they don't prove what happened before collection, and this is not a certified forensic tool.
- Findings are leads from readable rules, not verdicts; clock estimates show how far clocks disagree, not which clock is right (the analyst chooses the trusted clock).
- Benchmarks are machine time on one machine, not investigator time.
