# Phase 4 Exit Report — K-Step Simulation & MITRE ATT&CK Mapping
**Persona used:** Cyber Threat Intelligence Analyst, MITRE ATT&CK specialist
**Status:** COMPLETE

## What was built
- Autoregressive rollout engine (`src/simulation/rollout.py`) executing $K$-step forward simulation ($K=10$ default).
- Confidence decay function ($0.85^k$) reducing prediction certainty over larger forecast horizons.
- MITRE ATT&CK tactical mapping rule layer (`src/simulation/mitre_mapping.py`) covering 5 simplified stages: *Reconnaissance*, *Initial Access*, *Lateral Movement*, *Command & Control*, *Exfiltration*.
- Defensible mapping documentation (`docs/MITRE_MAPPING.md`).

## How it was tested/verified
- Inference function `run_inference()` verified to return complete probability timeline, stage progression, and confidence decay arrays.

## Constraint re-check
- [x] K-step forward simulation supported with explicit confidence decay.
- [x] MITRE stage mapping documented and aligned with official PS text.
