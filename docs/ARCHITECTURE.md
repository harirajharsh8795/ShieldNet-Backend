# NetGuard System Architecture Document
**Smart India Hackathon 2026 — Problem Statement SIH26153 (NTRO)**
**System Name:** NetGuard World-Model Network-Attack-Forecasting System

---

## 1. System Overview & Paradigm Shift

Static intrusion detection systems (IDS) classify historical network traffic as benign or malicious *after* compromise occurs. **NetGuard** introduces a generative **World Models** paradigm ($P(S_{t+1} \mid S_t)$) that models temporal network state dynamics, projecting multi-step future state trajectories to predict infiltration progression **before compromise completes**.

```
                           +-----------------------------------+
                           |  Network Telemetry Data           |
                           |  (PCAP or NetFlow/IPFIX CSV)      |
                           +-----------------+-----------------+
                                             |
                                             v
                           +-----------------+-----------------+
                           | Dual-Level Feature Extraction     |
                           |  • Flow-Level (80+ metrics)       |
                           |  • Packet-Level (TTL, Win, Ent)  |
                           +-----------------+-----------------+
                                             |
                                             v
                           +-----------------+-----------------+
                           | Fixed Time-Window Sequencer       |
                           | Aggregates flows into S_t vectors|
                           +-----------------+-----------------+
                                             |
                                             v
                           +-----------------+-----------------+
                           | LSTM World Model Engine           |
                           | Primary: Next-State Loss MSE      |
                           | Aux: MITRE Stage Classifier Head  |
                           +--------+----------------+--------+
                                    |                |
             +----------------------+                +----------------------+
             |                                                              |
             v                                                              v
+------------+--------------------+                       +-----------------+--------------------+
| K-Step Forward Simulator        |                       | Enforced Explainability Engine     |
| • Temporal Probability Curve    |                       | • SHAP / Gradient Feature Attribution|
| • Confidence Decay (0.85^k)     |                       | • Plain-Language NLG Summary       |
+------------+--------------------+                       +-----------------+--------------------+
             |                                                              |
             +----------------------+                +----------------------+
                                    |                |
                                    v                v
                           +--------+----------------+--------+
                           | Streamlit Offline Dashboard GUI   |
                           | Zero External Network Calls       |
                           +-----------------------------------+
```

---

## 2. Key Architecture Components

### A. Dual-Level Telemetry Parsing Layer (`src/ingestion/` & `src/features/`)
- **Flow-Level Features:** Extracted via CICFlowMeter schema (80+ parameters: flow duration, packet counts, bytes/sec, bidirectional IAT statistics, flag counts, TCP window sizes).
- **Packet-Level Features:** Parsed via Scapy/dpkt (TTL mean/variance, TCP window std, IP fragmentation ratio, payload size Shannon entropy, port scan pattern scores).

### B. State Sequencer & Preprocessing (`src/features/sequencer.py`, `preprocessing.py`)
- Groups telemetry into non-overlapping 10-second time windows ($S_t$).
- Constructs overlapping sequences of length $L=20$ windows ($S_{t-19}, \dots, S_t$).
- Applies `StandardScaler` fit **exclusively on the training split** to guarantee zero data leakage.

### C. World Model Core Engine (`src/world_model/`)
- **Architecture:** 2-layer stacked LSTM ($h=256$, dropout $0.3$).
- **Primary Objective (Dynamics Learning):** Minimizes MSE on next-state vector $S_{t+1}$ prediction: $\mathcal{L}_{\text{state}} = \| \hat{S}_{t+1} - S_{t+1} \|_2^2$.
- **Auxiliary Objective:** Predicts MITRE ATT&CK stage logits via linear head ($\mathcal{L}_{\text{aux}}$).
- **Total Loss:** $\mathcal{L}_{\text{total}} = \mathcal{L}_{\text{state}} + 0.3 \cdot \mathcal{L}_{\text{aux}}$.

### D. K-Step Forward Simulator (`src/simulation/`)
- Autoregressively feeds predictions back into the model for $K$ steps ($K=10$ default).
- Generates: (1) Time-series probability timeline, (2) MITRE ATT&CK stage sequence, (3) Per-step confidence decay ($0.85^k$).

### E. Enforced Explainability Layer (`src/explainability/`)
- Generates SHAP / gradient attributions for every forecast.
- **Constraint C2 Enforcement:** `enforce_explanation()` raises `ExplanationMissingError` if any prediction lacks attribution.

---

## 3. Strict Operating & Defense Constraints Compliance

| Constraint | Implementation Guarantee | Verification Mechanism |
|---|---|---|
| **C1: Passive Analysis** | Ingestion reads PCAP/CSV offline; zero packet injection code. | Inspection of `src/ingestion/` |
| **C2: Mandatory Explanation** | `enforce_explanation()` called in core inference loop. | `tests/test_explainability_enforced.py` |
| **C3: Dynamics Learning** | Diagnostic script evaluates MSE reduction vs baseline across epochs. | `scripts/prove_world_model.py` |
| **C4: Zero Cloud Call** | Offline Streamlit app; zero external API dependencies. | Tested with networking disabled |
| **C5: Logistic Regression Baseline** | Trained on identical flattened features. | `models/baseline_metrics.json` |

---

## 4. Benchmark Performance Target Structure

| Model | F1-Score (Weighted) | Precision (Weighted) | Recall (Weighted) | False Positive Rate |
|---|---|---|---|---|
| **Logistic Regression Baseline** | ~0.82 | ~0.84 | ~0.81 | ~0.08 |
| **NetGuard World Model (LSTM)** | **>0.92** | **>0.93** | **>0.91** | **<0.03** |
