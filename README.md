# AIORI-3 Hackathon Projects

This repository contains code and resources developed for the AIORI-3 hackathon.

## ORISECT — PS-013 / TC081

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="src/incident_timeline/brand/orisect-lockup.svg">
  <img src="src/incident_timeline/brand/orisect-lockup-ink.svg" alt="ORISECT" width="280">
</picture>

ORISECT (formerly TRACEFUSE) reconstructs incidents from system and web access logs while preserving original evidence, source SHA-256 hashes, and a hash-chained custody log. The Python engine writes a normalized, UTC-sorted and line-traceable timeline. The dashboard adds explainable findings (each citing its exact evidence lines and an ATT&CK technique), cross-source entity pivots and a live custody-chain view. Logs in a format ORISECT doesn't know are still preserved; its rule assistant proposes a parser rule from their lines, and an analyst tests and approves it, which is recorded in the custody log. The PDF report opens with the findings, each citing the line and file hash behind it. The dashboard, PDF/JSON exports and the engine's synthetic validation scenarios are documented in [`src/README.md`](src/README.md).

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
