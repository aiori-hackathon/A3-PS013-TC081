# AIORI-3 Hackathon Projects

This repository contains code and resources developed for the AIORI-3 hackathon.

## TRACEFUSE — PS-013 / TC081

TRACEFUSE reconstructs incidents from system and web access logs while preserving original evidence, source SHA-256 hashes, and a hash-chained custody log. The Python engine writes a normalized, UTC-sorted and line-traceable timeline. The dashboard adds explainable findings (each citing its exact evidence lines and an ATT&CK technique), cross-source entity pivots and a live custody-chain view. The dashboard, PDF/JSON exports, and three reproducible synthetic test scenarios are documented in [`src/README.md`](src/README.md).

### Quick start

```bash
python -m pip install -r requirements.txt
python -m pip install -e .

# Generate and validate three synthetic incidents
incident-timeline demo --output cases/demo-scenarios

# Open all three demo cases in the local browser (switch with the case picker)
incident-timeline serve cases/demo-scenarios
```

Proposal resources: [presentation](A3-PS013-TC081-presentation.pdf) and [proposed structure](Proposed-structure-hackathon.pdf).

## Team introduction video

https://youtu.be/XqBitlqQr0g
