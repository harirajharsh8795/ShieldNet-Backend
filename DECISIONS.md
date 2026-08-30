# DECISIONS.md — Non-Obvious Assumptions & Substitutions Log

> Every non-obvious engineering decision is logged here with rationale.
> Append-only: do not edit or delete past entries.

---

## Phase 0 — Environment & Data Acquisition

### D-001: Dataset Mirror Sources
**Date:** 2026-08-26
**Decision:** Use Kaggle CSV mirror for CIC-IDS-2018 and GitHub CSV mirror for CTU-13 as primary data sources.
**Rationale:** Direct AWS S3 sync for CIC-IDS-2018 requires large bandwidth and the original source has reliability issues. The Kaggle mirror (`solarmainframe/ids-intrusion-csv`) contains the same CICFlowMeter-extracted CSV files. For CTU-13, the Stratosphere IPS bulk tarball is ~30GB; the GitHub CSV mirror (`imfaisalmalik/CTU13-CSV-Dataset`) provides pre-processed flow records suitable for our pipeline.
**Impact:** No loss of feature coverage — both mirrors contain the same flow-level features. Packet-level features will be derived/proxied from available metadata (logged separately in D-002).

### D-002: Packet-Level Feature Derivation
**Date:** 2026-08-26
**Decision:** Since the CSV mirrors don't include raw PCAP data, packet-level features (TTL variance, TCP window size, fragment flags, etc.) will be derived from available metadata columns where possible, and synthesised as proxy features where direct measurement is unavailable.
**Rationale:** The PS requires both flow-level AND packet-level features. Using only flow-level would be a spec violation. The proxy approach is documented transparently and the PCAP-ingestion path is built and ready for real packet data.
**Impact:** Proxy features are clearly flagged in the data dictionary and code comments. The architecture supports real packet-level extraction via Scapy when raw PCAP is available.

### D-003: Python Environment
**Date:** 2026-08-26
**Decision:** Use Python 3.10+ with pip + venv (not conda).
**Rationale:** Simpler dependency chain, easier fresh-clone reproducibility, no conda-specific issues.

### D-004: Deep Learning Framework
**Date:** 2026-08-26
**Decision:** PyTorch (not TensorFlow) for the World Model.
**Rationale:** Better debugging experience, native SHAP/Captum integration for explainability, and more natural sequence modelling APIs for LSTM/Transformer architectures.

---

## Phase 9 / Follow-up — Dataset Expansion & Model Stability

### D-005: Cross-Dataset Training Expansion (CSE-CIC-IDS2018 Integration)
**Date:** 2026-08-29
**Decision:** Keep `world_model_v1.pt` (single-scale GRU trained on in-distribution CICIDS2017) as the locked submission baseline; do NOT merge CSE-CIC-IDS2018 samples into the primary training set.
**Rationale:** We extracted 11,641 real rare-attack samples across 11 classes from CSE-CIC-IDS2018 CSVs, aligned the 77 flow features, and retrained the exact same architecture. While shuffle degradation significance increased to $+4.07\sigma$ and dynamics MSE remained tight (1.1955), mixing AWS EC2 cloud telemetry (2018) with physical on-premises network telemetry (2017) introduced covariate domain shift that pulled in-distribution Balanced Accuracy down from 79.15% to 58.10% (-21.05%) and Overall Accuracy down from 89.50% to 74.80% (-14.70%).
**Impact:** `world_model_v1.pt` is retained as the locked baseline, achieving peak tail-class sensitivity (79.15% Balanced Accuracy). CSE-CIC-IDS2018 is retained strictly as an independent cross-dataset generalization benchmark (where the locked model achieves 80.36% Threat Precision and 0.6956 F1), preserving rigorous cross-domain validation integrity without polluting in-distribution baselines.

### D-006: Phase 10 Unified Model Tournament Winner (Locking GRU + Attention)
**Date:** 2026-08-30
**Decision:** Declare the Single-Scale ($L=3$) GRU + Temporal Attention World Model (`world_model_v1.pt`) the decisive tournament winner and sole submission architecture.
**Rationale:** Under a unified, shared evaluation harness (`src/tournament/run_candidate.py`) across all 4 locked evaluation benchmarks (CICIDS2017, UNSW-NB15, CSE-CIC-IDS2018, DARPA 1998 PCAP), we trained and evaluated 9 candidate model families:
1. **Explainability Gate (Constraint C2):** GraphSAGE+GRU was disqualified due to opaque graph neighborhood aggregations causing flow attribution opacity and a $4.2\times$ latency penalty.
2. **Composite Ranking:** GRU + Temporal Attention achieved the #1 composite rank (1.50) across all 4 evaluation sets, leading the field in In-Distribution Balanced Accuracy (79.15%), UNSW-NB15 Zero-Shot ROC (0.8026), and DARPA 1998 PCAP Threat Detection (97.46%).
3. **Operational Viability:** GRU achieved a 4.03 ms 5-step rollout latency ($16.3\times$ faster than VAE+MDN-RNN at 65.88 ms), ensuring smooth 60 FPS interactive dashboard counterfactual rollouts with zero frame drops.
**Impact:** `world_model_v1.pt` is permanently locked as the winning model. Candidate code is preserved in `src/tournament/candidates/` for jury transparency, while large non-winning checkpoints are cleaned from disk.


