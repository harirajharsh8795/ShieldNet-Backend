# 🛡️ ShieldNet — Sovereign AI World Model for Predictive Cyber Defense

> **Smart India Hackathon 2026 — Problem Statement SIH-26153**
> **Organization:** National Technical Research Organisation (NTRO) | **Theme:** Blockchain & Cybersecurity | **Category:** Software
> **Team:** ProtocolX | **Team ID:** 130971

---

## 📋 NTRO Evaluation Deliverables — Quick Access

| # | SIH Mandated Deliverable | Location | Status |
|:---:|:---|:---|:---:|
| 1 | **Source Code (GitHub)** | [`harirajharsh8795/ShieldNet-Backend`](https://github.com/harirajharsh8795/ShieldNet-Backend) · [`KajalChaudhary2326/ShieldNet`](https://github.com/KajalChaudhary2326/ShieldNet) | ✅ Live |
| 2 | **README with Setup Instructions** | [`README.md §5 Quick-Start`](#5-quickstart--setup-instructions) · `run_offline.bat` / `run_offline.sh` | ✅ Complete |
| 3 | **Architecture Document (Max 2 Pages)** | [`docs/ARCHITECTURE_DOCUMENT_2PAGE.md`](docs/ARCHITECTURE_DOCUMENT_2PAGE.md) | ✅ 2 Pages |
| 4 | **Demo Video (Max 2 Minutes)** | [`docs/demo_video_script.md`](docs/demo_video_script.md) | ✅ 120s Script |
| 5 | **Technical Presentation (Max 5 Slides)** | [`docs/SLIDES_5SLIDES_OUTLINE.md`](docs/SLIDES_5SLIDES_OUTLINE.md) | ✅ 5 Slides |

---

## 🎯 1. Problem Statement — What We Solve (PS-26153)

Traditional IDS / ML classifiers treat every network flow **in isolation**: classify one packet → binary benign/malicious label → discard all temporal and causal context. An infiltration is **not** a single anomalous packet — it is a process unfolding over time: port reconnaissance → credential brute-force → lateral movement → exfiltration.

**ShieldNet** implements a **World Model** — an AI architecture that learns the internal causal simulation of how network state evolves:

```
P(S_t+1 | S_t) — Given today's network state, what is tomorrow's?
```

By rolling this forward **K=1..10 steps** (~10s to 100s per step), ShieldNet **forecasts** infiltrations before the attacker completes the kill chain.

### PS-26153 Requirement Coverage

| PS-26153 Requirement | ShieldNet Implementation |
|:---|:---|
| Represent network state as feature vectors | **84-Dimensional State Vector** — 77 NetFlow/IPFIX + 7 PCAP packet features |
| Learn P(S_t+1 \| S_t) using LSTM / Transformer / GNN | **3-Layer GRU (H=512) + 8-Head Temporal Self-Attention** — learns state-transition dynamics |
| K-step forward rollout + infiltration probability | **K=1..10 Autoregressive Rollout** — outputs infiltration probability timeline |
| MITRE ATT&CK stage mapping | **Symbolic MITRE Reasoner** maps predicted states to: Recon → Initial Access → Lateral Movement → C2 → Exfiltration |
| Explainability (SHAP / Attention) | **Dual-Engine XAI:** Captum Integrated Gradients (neural) + SHAP (tabular). Black-box output raises system error |
| Offline / Air-Gapped execution | **100% air-gapped** — zero cloud API dependencies; single-command `run_offline.bat` launch |
| Benchmark vs. logistic regression baseline | **9-Cell Matrix:** GRU+Attention vs Plain LSTM vs Logistic Regression on identical 84-D feature vectors |

---

## 📊 2. Verified Benchmark Results

### 2A. In-Distribution Benchmark — CIC-IDS-2017 (Primary Evaluation, N=10,909)

> **Source:** `models/checkpoints/MODEL_BENCHMARK_9CELL.json` · Evaluated: 2026-09-19 UTC · Device: Intel Xeon / Core Edge CPU (no GPU)

| Metric | Logistic Regression (Baseline) | Plain LSTM (Ablation) | **ShieldNet GRU+Attention (Champion)** | Advantage |
|:---|:---:|:---:|:---:|:---|
| **Overall Accuracy** | 91.66% | 94.20% | **97.85%** | +6.19% over baseline |
| **Balanced Accuracy** | 47.81% | 68.40% | **90.64%** | +42.83% absolute gain |
| **Macro F1** | 0.3014 | 0.3648 | **0.4851** | +18.4% over LogReg |
| **Weighted F1** | 0.8998 | 0.9335 | **0.9725** | High-volume discrimination |
| **Threat Precision** | 84.21% | 88.74% | **94.85%** | Minimizes alert fatigue |
| **Attack Recall** | 81.15% | 89.32% | **96.40%** | Catches 96.4% of intrusions |
| **False Positive Rate** | 4.12% | 1.85% | **0.38%** | 91% fewer false alerts |
| **Brier Score** | 0.0418 | 0.0245 | **0.0118** | Superior probability calibration |
| **Inference Latency (B=1)** | 0.082 ms | 1.269 ms | **1.84 ms** | Real-time edge processing |
| **Training Time** | 1.2s | 142.5s | **98.3s** | ~31% faster than LSTM |
| **Model Parameters** | 1,105 | 304,680 | **260,904** | 14.4% fewer params than LSTM |

> **Benchmark script:** `python scripts/benchmarks/benchmark_gru_vs_lstm_vs_logreg.py`

---

### 2B. SOTA Champion — Fused Pipeline (world_model_sota99_champion.pt)

> **Source:** `models/checkpoints/FINAL_BENCHMARK_SOTA99.json` · Architecture: 3-Layer GRU H=512 + 8-Head Attention + Latent Stacking

| Metric | LogReg Baseline | **ShieldNet SOTA Champion** |
|:---|:---:|:---:|
| **Threat Accuracy** | 90.99% | **99.75%** |
| **Threat Macro F1** | 0.7434 | **0.9943** |
| **Weighted Precision** | — | **99.76%** |
| **Weighted Recall** | — | **99.75%** |
| **False Positive Rate** | 2.13% | **0.28%** |
| **MITRE Stage Accuracy** | — | **99.88%** |
| **MITRE Stage Macro F1** | — | **0.9936** |

**MITRE Stage F1 Breakdown (SOTA Champion):**

| MITRE Stage | F1-Score |
|:---|:---:|
| Benign Traffic | 0.9993 |
| Reconnaissance (TA0043) | 0.9900 |
| Initial Access (TA0001) | 0.9991 |
| Lateral Movement (TA0008) | 0.9973 |
| Command & Control (TA0011) | 0.9773 |
| Impact / Exfiltration (TA0010) | 0.9986 |

---

### 2C. CTU-13 Botnet Benchmark (Cross-Dataset)

> **Source:** `models/checkpoints/GRAND_OMNI_ALL_DATASETS_METRICS.json` · Held-Out Scenarios: 11, 12, 13 (NSIS.ay, Virut, Rbot)

| Metric | Value |
|:---|:---:|
| ROC-AUC | **0.9996** |
| Botnet Recall | **100%** |
| Accuracy | **98.05%** |
| Macro F1 | **0.9406** |

---

### 2D. Temporal Dynamics Significance — Shuffle Ablation (20 seeds)

> **Source:** `models/checkpoints/tiebreaker_final_decision.json` · This proves ShieldNet genuinely exploits temporal ordering — not just statistical patterns.

| System | Intact Balanced Acc | Mean (Shuffled) | Drop | **Sigma** |
|:---|:---:|:---:|:---:|:---:|
| World Model v1 alone | 79.15% | 68.09% | −11.05% | 2.53σ |
| **Dual-Engine Ensemble (Champion)** | **83.12%** | **68.85%** | **−14.27%** | **3.92σ** |

> **Interpretation:** +3.92σ above shuffled baseline proves that temporal ordering of traffic sequences is the genuine source of ShieldNet's performance gain — not memorized signatures.

---

### 2E. K-Step Forward Rollout Latency

> **Source:** `models/checkpoints/GROUND_TRUTH_FINAL.json`

| Operation | Latency |
|:---|:---:|
| K=5 step forward rollout (mean, 200 runs) | **4.81 ms** |
| Single-sample inference | **0.015 ms** |
| Ensemble (WM + LogReg) inference | **0.0155 ms** |

---

## 🔬 3. World Model Architecture

### 3.1 Dual-Level Feature Extraction (84-D State Vector)

The problem statement mandates **both** flow-level and packet-level features:

| Level | Source | Features | Count |
|:---|:---|:---|:---:|
| **Flow-Level** | NetFlow / IPFIX | src/dst IP-port pairs, TCP flag bitmask (SYN/ACK/FIN/RST/PSH/URG), bytes/packets per flow, duration, IAT mean/var/max, bidirectional ratios, protocol | **77** |
| **Packet-Level** | PCAP (Scapy/PyShark) | TTL variance, TCP window size, IP fragment flags, payload size distribution, port-scan signatures, retransmission counts | **7** |
| **Combined** | Fused canonical vector | Normalised by Frozen Reference Scaler Guard | **84** |

**Why both?** Flow-level captures aggregate behaviour (SYN flood); packet-level exposes evasive timing patterns (slow reconnaissance designed to evade flow-based thresholds).

### 3.2 GRU World Model Core (Champion Architecture)

```
Input Sequence [S_t-L ... S_t] (84-dim, L=3 or L=10 timesteps)
        │
        ▼
┌────────────────────────────────────────────────────────┐
│           3-Layer GRU Encoder (H=512 each)             │
│  Layer 1: Low-level flow transition patterns            │
│  Layer 2: Attack-stage temporal dependencies            │
│  Layer 3: Multi-step kill-chain progression             │
└──────────────────────┬─────────────────────────────────┘
                       │
                       ▼
         8-Head Temporal Self-Attention Pooling
         (Dynamically weights S_{t-L:t} history
          — focuses on subtle early-stage recon)
                       │
             ┌─────────┴──────────┐
             ▼                    ▼
  Multi-Task Head A        Multi-Task Head B
  Attack Classification     State Dynamics
  (13 attack classes +      P(S_t+1 | S_t)
   MITRE stage mapping)     Huber loss = 0.096
```

**Why GRU over LSTM?**
1. **14.4% fewer parameters** — GRU merges forget/input gates into single update gate; single hidden state vs LSTM's dual (h_t, c_t)
2. **~31% faster training** — 98.3s vs 142.5s (fewer FLOPs per backward pass)
3. **Lower overfitting risk** — Extreme class imbalance (Botnets < 0.5% of flows) means excess LSTM parameters cause memorization on sparse attack classes
4. **Temporal attention pooling** — Instead of final-timestep only, dynamically weights S_{t-L:t} to detect early-stage slow-scan reconnaissance

### 3.3 K-Step Autoregressive Rollout (Core World Model Property)

```python
# Pseudo-code of forward rollout (src/world_model/model.py)
for k in range(1, K+1):
    S_pred = world_model.forward(S_current)   # P(S_t+k | S_t+k-1)
    infiltration_prob[k] = S_pred.threat_prob  # rising probability timeline
    mitre_stage[k] = mitre_reasoner.decode(S_pred)  # TA0043 → TA0001 → ...
    S_current = S_pred.detach()
# Output: 10-step = 100-second infiltration probability forecast
```

### 3.4 SIERL Blockchain Trust Ledger

Every prediction is **immutably sealed** on the **SIERL** (*ShieldNet Immutable Evidence & Response Ledger*) blockchain:

```
┌─────────────────────────────────────────────────────────┐
│  SIERL Block — SHA-256 Multi-Artifact Hash Chain        │
│                                                         │
│  evidence_hash   : SHA-256(raw PCAP / telemetry input)  │
│  model_hash      : SHA-256(world_model_sota99.pt)       │
│  prediction_hash : SHA-256(attack class + K-step probs) │
│  xai_hash        : SHA-256(SHAP / IG feature attrs)     │
│  analyst_sig     : Human approval or override signature  │
│  prev_hash       : Links to prior block (tamper chain)   │
│  tamper_detect   : Detects any chain break in < 0.12s   │
└─────────────────────────────────────────────────────────┘
```

**Legal Compliance:**
- **Bharatiya Sakshya Adhiniyam (BSA) 2023 — Section 63** — Tamper-proof electronic forensic evidence for digital prosecution
- **MeitY National Cyber Security Strategy** — Aligned with India's sovereign AI defense framework
- **NCIIPC CII Protection Guidelines** — Designed to protect power grids, SCADA systems, financial infrastructure

---

## 🗂️ 4. Feature Pipeline & Datasets

### 4.1 Datasets Used

| Dataset | Sequences (Training) | Attack Types | Role |
|:---|:---:|:---|:---|
| **CIC-IDS-2017** | 97,935 train / 10,909 test | DDoS, DoS, PortScan, Botnet, Brute-Force, XSS, Web Attacks | Primary training & evaluation |
| **CSE-CIC-IDS2018** | 149,997 transitions | Brute-Force, Infiltration, DoS variants, Botnet | Secondary training |
| **CTU-13** | 13 scenarios | Botnet (IRC-C2, P2P, HTTP-C2) — held-out scenarios 11,12,13 for test | Botnet generalization |
| **UNSW-NB15** | 82,322 transitions | Fuzzers, Exploits, Backdoors, DoS, Shellcode | Cross-dataset OOD evaluation |
| **DARPA 1998** | Military PCAPs | Insider threats, Network probes | Domain robustness |

**Total training sequences:** 41,678 (5-dataset fused grand omni training, `world_model_grand_omni.pt`)

### 4.2 Feature Extraction

```bash
# From raw PCAP files
python scripts/extract_pcap_features.py --input data/captures/ --output data/processed/

# From CSV flow records (CIC-IDS format)
python scripts/extract_csv_features.py --input dataset/ --output data/processed/
# Output: timestamped, normalised 84-dimensional feature matrices
```

---

## ⚡ 5. Quickstart & Setup Instructions

### Prerequisites

| Tool | Version | Purpose |
|:---|:---:|:---|
| **Python** | 3.10+ | Backend, ML models, FastAPI |
| **Node.js** | 18+ | React frontend dashboard |
| **Git** | Any | Repository cloning |

> All Python dependencies are in `requirements.txt`. A pre-populated `venv/` is included for offline use.

---

### Option A — One-Command Automated Launch (Recommended)

**Windows:**
```bat
run_offline.bat
```

**Linux / macOS:**
```bash
chmod +x run_offline.sh && ./run_offline.sh
```

This automatically:
1. Starts FastAPI backend + SIERL Ledger → `http://127.0.0.1:8000`
2. Starts React SOC Dashboard → `http://localhost:5173`
3. Opens browser at the dashboard

---

### Option B — Manual Step-by-Step

**Step 1 — Clone:**
```bash
git clone https://github.com/harirajharsh8795/ShieldNet-Backend.git
cd ShieldNet-Backend
```

**Step 2 — Python environment:**
```bash
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
```

**Step 3 — Start Backend (Terminal 1):**
```bash
python -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000 --reload
```
→ API docs available at `http://127.0.0.1:8000/docs`

**Step 4 — Start Frontend (Terminal 2):**
```bash
cd frontend
npm install
npm run dev
```
→ SOC Dashboard at `http://localhost:5173`

---

### Option C — Verification & Benchmark Tests

```bash
# 9-Cell GRU vs LSTM vs LogReg benchmark (mandated PS-26153 deliverable)
python scripts/benchmarks/benchmark_gru_vs_lstm_vs_logreg.py

# SIERL blockchain unit tests (6/6)
python -m pytest tests/test_sierl_blockchain.py -p no:playwright -p no:timeout -v

# Full test suite
python -m pytest tests/ -v

# Cross-dataset evaluation
python scripts/eval_cross_dataset.py

# MITRE stage accuracy evaluation
python scripts/eval_mitre_stage_cross_dataset.py
```

---

### SOC Portal Credentials

| Role | Email | Password | Level |
|:---|:---|:---|:---:|
| **CISO / Admin** | `admin@shieldnet.local` | `Admin@123` | 5 |
| **SOC Analyst** | `analyst@shieldnet.local` | `Analyst@123` | 3 |
| **Forensic Auditor** | `auditor@shieldnet.local` | `Auditor@123` | 4 |

---

## 📂 6. Repository Structure

```
ShieldNet/
├── run_offline.bat                       # One-command Windows launch
├── run_offline.sh                        # One-command Linux/macOS launch
├── requirements.txt                      # Python dependencies
├── train.py                              # Model training entry point
│
├── frontend/                             # React + TypeScript + Vite SOC Dashboard
│   ├── src/pages/
│   │   ├── DashboardPage.tsx             # Executive Overview & Telemetry HUD
│   │   ├── LiveMonitorPage.tsx           # Real-time flow stream & OOD drift alerts
│   │   ├── ComparePage.tsx               # 9-Cell Benchmark table (GRU vs LSTM vs LogReg)
│   │   ├── BlockchainAuditPage.tsx       # SIERL Block Explorer & Evidence Verifier
│   │   └── UploadPage.tsx                # PCAP & CSV drag-and-drop ingestion
│   └── src/data/api.ts                   # Production API client (offline fallbacks)
│
├── src/
│   ├── api/server.py                     # FastAPI REST server (2198 lines)
│   ├── world_model/
│   │   ├── model.py                      # 3-Layer GRU (H=512) + 8-Head Attention
│   │   └── dataset.py                    # Temporal window sequence extractor (L=3/10)
│   ├── features/
│   │   ├── fusion.py                     # 84-D dual-level feature fusion
│   │   ├── packet_features.py            # 7 PCAP-derived packet features
│   │   ├── ood_detector.py               # Out-of-distribution & drift guard
│   │   ├── schema_adapter.py             # Cross-dataset normalizer (UNSW, CTU-13, CIC)
│   │   └── scaler_guard.py               # Frozen reference normalisation safeguard
│   ├── ledger/
│   │   ├── sierl_ledger.py               # SHA-256 hash-chained SIERL blockchain
│   │   ├── evidence_hasher.py            # Multi-artifact SHA-256 hasher
│   │   └── orchestrator.py              # SOAR firewall actuator (iptables, nftables)
│   ├── explainability/
│   │   ├── feature_attribution.py        # Dual-engine XAI: Integrated Gradients + SHAP
│   │   └── mitre_kg.py                   # Symbolic MITRE ATT&CK Reasoner
│   ├── mitigation/
│   │   ├── counterfactual_engine.py      # 5-scenario what-if latent-space simulation
│   │   └── defense_synthesizer.py        # Sovereign defense action generator
│   ├── auth/security.py                  # HMAC-SHA256 JWT + RBAC
│   └── database/db.py                    # SQLite + SQLAlchemy persistent incident DB
│
├── scripts/
│   ├── benchmarks/
│   │   └── benchmark_gru_vs_lstm_vs_logreg.py  # 9-Cell benchmark generator
│   └── [90+ analysis, training, eval scripts]
│
├── models/checkpoints/
│   ├── world_model_sota99_champion.pt    # SOTA champion (99.75% acc, 0.28% FPR)
│   ├── world_model_grand_omni.pt         # 5-dataset fused omni model
│   ├── MODEL_BENCHMARK_9CELL.json        # Verified 9-cell benchmark JSON
│   ├── FINAL_BENCHMARK_SOTA99.json       # SOTA champion metrics JSON
│   ├── tiebreaker_final_decision.json    # 20-seed shuffle ablation proof
│   └── sierl_ledger.json                 # Committed blockchain ledger state
│
├── docs/
│   ├── ARCHITECTURE_DOCUMENT_2PAGE.md    # SIH mandated 2-page architecture doc
│   ├── SLIDES_5SLIDES_OUTLINE.md         # SIH mandated 5-slide outline
│   ├── PS_COMPLIANCE_MATRIX.md           # PS-26153 clause compliance matrix
│   └── EXAMINER_DEFENSE_CHEATSHEET.md    # Top 10 NTRO Q&A preparation
│
└── tests/
    └── test_sierl_blockchain.py          # 6/6 unit tests for ledger & tamper detection
```

---

## 🔒 7. PS-26153 Constraint Compliance Matrix

| Constraint | PS-26153 Requirement | ShieldNet Implementation | Status |
|:---:|:---|:---|:---:|
| **C1** | Passive analysis only | Passive NetFlow/PCAP ingestion; zero active port scanning | ✅ Verified |
| **C2** | Mandatory explainability | Dual-engine XAI (Integrated Gradients + SHAP); black-box output raises `ExplainabilityError` | ✅ Verified |
| **C3** | World model temporal dynamics | Learns P(S_t+1\|S_t); **+3.92σ shuffle-significance** ablation proves genuine temporal learning | ✅ Verified |
| **C4** | 100% Offline / Air-Gapped | Zero cloud dependencies; fully operational under network isolation | ✅ Verified |
| **C5** | Baseline benchmarking | 9-cell matrix: GRU+Attention vs Plain LSTM vs Logistic Regression on identical 84-D features | ✅ Verified |
| **C6** | Immutable audit trail | SIERL SHA-256 hash-chained blockchain; tamper detection < 0.12s; BSA 2023 Sec 63 compliant | ✅ Verified |

---

## 🌐 8. Government & Statutory Alignment

- **MeitY National Cyber Security Strategy** — Aligned with India's national framework for sovereign AI-based cyber defense
- **NCIIPC CII Protection Guidelines** — Designed to protect Critical Information Infrastructure: power grids, SCADA, telecom, financial systems
- **Bharatiya Sakshya Adhiniyam (BSA) 2023 — Section 63** — SIERL blockchain generates legally admissible tamper-proof digital forensic evidence for prosecution
- **Atmanirbhar Bharat** — 100% sovereign, no foreign cloud dependencies, fully air-gapped
- **CERT-In 6-Hour Reporting Mandate** — Automated incident dossier export accelerates mandatory breach notification

---

## 📜 License & References

Developed for **Smart India Hackathon 2026 (SIH-26153)** under the auspices of the **National Technical Research Organisation (NTRO)**.

| Reference | Citation |
|:---|:---|
| **GRU Architecture** | Cho et al. (2014). *Learning Phrase Representations using RNN Encoder–Decoder* |
| **Integrated Gradients XAI** | Sundararajan et al. (2017). *Axiomatic Attribution for Deep Networks* |
| **MITRE ATT&CK** | MITRE Corporation. `https://attack.mitre.org` |
| **CIC-IDS-2017/2018** | Canadian Institute for Cybersecurity, UNB |
| **CTU-13** | Garcia et al. (2014). Czech Technical University |
| **UNSW-NB15** | Moustafa & Slay (2015). University of New South Wales |
| **BSA 2023 Sec 63** | Bharatiya Sakshya Adhiniyam, 2023 (Electronic Evidence Admissibility) |
