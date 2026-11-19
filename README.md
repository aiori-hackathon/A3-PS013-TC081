# AIORI-3 Hackathon Projects

This repository contains code and resources developed for the AIORI-3 hackathon.

## ORISECT — PS-013 / TC081

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="src/incident_timeline/brand/orisect-lockup.svg">
  <img src="src/incident_timeline/brand/orisect-lockup-ink.svg" alt="ORISECT" width="280">
</picture>

ORISECT (formerly TRACEFUSE) reconstructs incidents from system and web access logs while preserving original evidence, source SHA-256 hashes, and a hash-chained custody log. The Python engine writes a normalized, UTC-sorted and line-traceable timeline. The dashboard adds explainable findings (each citing its exact evidence lines and an ATT&CK technique), cross-source entity pivots and a live custody-chain view. Logs in a format ORISECT doesn't know are still preserved; its rule assistant proposes a parser rule from their lines, and an analyst tests and approves it, which is recorded in the custody log. The PDF report opens with the findings, each citing the line and file hash behind it. The dashboard, PDF/JSON exports and the engine's synthetic validation scenarios are documented in [`src/README.md`](src/README.md).

**Try it live: [orisect-varaxis.vercel.app](https://orisect-varaxis.vercel.app)**. Upload the [`demo-evidence/`](demo-evidence/README.md) folder and follow its walkthrough. The hosted demo keeps investigations for a few hours; don't upload real or sensitive logs to it.

### What it does

| Stage | ORISECT |
| --- | --- |
| **Preserve** | Each log is copied byte for byte, hashed with SHA-256, made read-only and recorded in a hash-chained custody log. Every later action (rules, clock corrections, verification) is a custody record too. |
| **Normalize** | Linux auth/syslog (RFC 3164, ISO, RFC 5424) and Apache/Nginx access logs, including gzip-rotated files. Time zones by IANA name or offset, with autocomplete; daylight-saving ambiguity and inferred years are flagged, never hidden. |
| **Teach** | A format ORISECT doesn't know is kept as evidence; the rule assistant proposes a parser rule from its lines, the analyst tests and approves it, and the approval is a custody record. |
| **Correct clocks** | Clock skew is measured automatically: events from different logs that share a client address are paired and the offset most of them agree on is found, with the pairs shown as evidence. One click applies it, recorded in custody. |
| **Reconstruct** | One UTC timeline across all sources, searchable and filterable, with a drag-to-filter density strip; every event links to its original line and file hash. |
| **Explain** | Readable rules raise findings (brute force, web shells, credential access, new admin accounts, suspicious cron, web-to-SSH pivots, large uploads), each citing its exact evidence lines, an ATT&CK technique and its attack stage. The **incident storyline** draws them on a time axis by stage, with the attack chain in words. |
| **Report** | PDF report, JSON export, and an **evidence bundle**: the logs, custody chain, timeline, report, manifest and `SHA256SUMS` in one ZIP that anyone can check with `sha256sum -c`, no ORISECT needed. |

### Validation and benchmarks

**113 automated tests** (pytest) cover the parsers, time handling, custody chain and tamper detection, findings, rules, clock-skew estimation and correction, the evidence bundle, the web API, the hosted deployment's case restore, and the browser-side engines. Pages are checked in Chromium at desktop and phone widths, in both themes. Details: [`docs/VALIDATION.md`](docs/VALIDATION.md).

On independently published data, Elastic's [NGINX sample logs](https://github.com/elastic/examples/tree/6d86454ebb7a850bcd7e80abe86fe683370018a6/Common%20Data%20Formats/nginx_logs) (SHA-256 `52683243…46937df`), through the web app's own upload path, median of three fresh investigations each:

| | First 1,000 lines | Whole file, 51,462 lines |
| --- | ---: | ---: |
| Parsed | 1,000 (100%) | 51,462 (100%) |
| Import (hash, preserve, parse, build) | 0.064 s, **15,600 records/s** | 2.51 s, **20,500 records/s** |
| Search, `q=GET`, 50 per page | **2.1 ms** | **24 ms** |
| PDF report | 3.96 s | not measured (lists every event) |
| Evidence bundle | 4.27 s | not measured |
| Integrity verification | 0.7 ms, passed | 6.7 ms, passed |

Measured on a 4-vCPU Intel Xeon (2.1 GHz) Linux container with Python 3.13. Processing time is machine time, not investigator time. Reproduce with `python scripts/benchmark_external.py`; full results in [`docs/benchmarks/elastic-nginx-results.json`](docs/benchmarks/elastic-nginx-results.json).

### Demo video

[![ORISECT demo: reconstructing a simulated server breach from four logs](https://img.youtube.com/vi/cEEAu6GjtE0/maxresdefault.jpg)](https://youtu.be/cEEAu6GjtE0)

A 7-minute walkthrough of the [`demo-evidence/`](demo-evidence/README.md) investigation: preserving the evidence, teaching ORISECT the firewall's log format (which reveals a 48 MB data theft), how timestamps are normalized, measuring and correcting a clock running 187 s fast, and the PDF report. [Watch on YouTube](https://youtu.be/cEEAu6GjtE0).

### Quick start

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
incident-timeline app
```

Open the address it prints, choose **Add evidence**, and upload the [`demo-evidence/`](demo-evidence/README.md) folder: four logs from one simulated intrusion. Its README walks through the whole investigation step by step:
- preserving the evidence;
- teaching ORISECT a firewall format it can't read yet, which reveals the data theft;
- correcting a clock fault;
- exporting the report.

Proposal resources: [presentation](A3-PS013-TC081-presentation.pdf) and [proposed structure](Proposed-structure-hackathon.pdf).

## Team introduction video

https://youtu.be/XqBitlqQr0g
