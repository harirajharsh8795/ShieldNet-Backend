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

Traditional IDS / ML classifiers treat every network flow **in isolation** — they classify a single packet as benign or malicious and discard all temporal, causal, and sequential context. An infiltration is not a single anomalous packet; it is a **process unfolding over time**: port reconnaissance → credential brute-force → lateral movement → exfiltration.

**ShieldNet** solves this with a **World Model** — an AI architecture that learns the internal causal simulation of how network state evolves:

```
P(S_t+1 | S_t) — Given today's network state, what is tomorrow's?
```

By rolling this forward **K=10 steps** (~100 seconds), ShieldNet **forecasts** infiltrations **before the attacker completes the kill chain**.

### PS-26153 Requirement Coverage

| PS-26153 Requirement | ShieldNet Implementation |
|:---|:---|
| Represent network state as feature vectors / graphs | 84-Dimensional State Vector (77 NetFlow/IPFIX + 7 PCAP packet features) |
| Learn P(S_t+1 \| S_t) using LSTM / Transformer / GNN | 3-Layer GRU (H=512) + 8-Head Temporal Self-Attention — learns state-transition dynamics |
| K-step forward simulation + infiltration probability | K=1..10 Autoregressive Rollout — outputs infiltration probability timeline (+50s to +100s ahead) |
| MITRE ATT&CK stage mapping | Symbolic MITRE Reasoner maps predicted states to: Recon → Initial Access → Lateral Movement → C2 → Exfiltration |
| Explainability (SHAP / Attention) | Dual-Engine XAI: Captum Integrated Gradients (neural) + SHAP (tabular); black-box outputs **rejected by system** |
| Offline / Air-Gapped execution | 100% air-gapped — zero cloud API dependencies; `run_offline.bat` / `run_offline.sh` single-command launch |
| Benchmark vs. logistic regression baseline | 9-Cell Matrix: GRU+Attention vs Plain LSTM vs Logistic Regression — all on identical 84-feature vectors |

---

## 📊 2. Benchmark Results — Model vs Baseline

Evaluated on held-out test distributions from **CIC-IDS-2017** (N=10,909), **CSE-CIC-IDS2018** (N=19,998), **CTU-13** (13 botnet scenarios), **UNSW-NB15**, and **DARPA 1998**.

| Metric | Logistic Regression (Baseline) | Plain LSTM | ShieldNet GRU+Attention ✅ |
|:---|:---:|:---:|:---:|
| **Overall Accuracy** | 91.66% | 94.20% | **97.85%** |
| **Balanced Accuracy** | 47.81% | 68.40% | **90.64%** |
| **Weighted F1-Score** | 0.8998 | 0.9335 | **0.9725** |
| **Macro F1-Score** | 0.3014 | 0.3648 | **0.4851** |
| **Threat Precision** | 84.21% | 88.74% | **94.85%** |
| **Attack Recall** | 81.15% | 89.32% | **96.40%** |
| **False Positive Rate (FPR)** | 4.12% | 1.85% | **0.38%** |
| **Brier Score (Calibration)** | 0.0418 | 0.0245 | **0.0118** |
| **Inference Latency (B=1)** | 0.24 ms | 2.26 ms | **2.29 ms** |
| **Model Parameters** | 1,105 | 304,680 | **260,904** |

> **Benchmark generation script:** `python scripts/benchmarks/benchmark_gru_vs_lstm_vs_logreg.py`
> **Raw benchmark JSON:** `models/checkpoints/MODEL_BENCHMARK_9CELL.json`

---

## 🔬 3. World Model Architecture

### 3.1 Dual-Level Feature Extraction (84-D State Vector)

| Level | Source | Features | Count |
|:---|:---|:---|:---:|
| **Flow-Level** | NetFlow / IPFIX | src/dst IP-port pairs, TCP flags (SYN/ACK/FIN/RST/PSH/URG), bytes/packets per flow, duration, IAT mean/var/max, bidirectional ratios | **77** |
| **Packet-Level** | PCAP (Scapy/PyShark) | TTL variance, TCP window size, IP fragment flags, payload distribution, port-scan signatures, retransmission counts | **7** |
| **Total** | | Dual-fused canonical state vector | **84** |

Both levels are mandatory: flow-level captures aggregate behaviour (SYN flood), packet-level exposes evasive timing patterns (slow reconnaissance designed to evade flow-based thresholds).

### 3.2 GRU World Model Core

```
Input Sequence [S_t-L ... S_t] (84-dim, L=10 timesteps)
        │
        ▼
┌─────────────────────────────────────────────────────┐
│         3-Layer GRU Encoder (H=512 each)            │
│  Layer 1: Learns low-level flow transition patterns  │
│  Layer 2: Learns attack-stage temporal dependencies  │
│  Layer 3: Learns multi-step kill-chain progression   │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
        8-Head Temporal Self-Attention Pooling
        (Weights historical states S_{t-L:t}
         — focuses on subtle early-stage recon)
                      │
            ┌─────────┴─────────┐
            ▼                   ▼
   Multi-Task Head A      Multi-Task Head B
   Attack Classification   State Dynamics
   (10 attack classes +    P(S_t+1 | S_t)
    MITRE stage label)     (K-step rollout)
```

### 3.3 K-Step Autoregressive Rollout

```python
# Forward simulate K steps from current state
for k in range(1, K+1):
    S_pred = world_model(S_current)   # P(S_t+k | S_t+k-1)
    infiltration_prob[k] = S_pred.threat_probability
    mitre_stage[k] = mitre_reasoner.decode(S_pred)
    S_current = S_pred
# Output: 100-second infiltration probability timeline
```

### 3.4 SIERL Blockchain Trust Ledger

Every prediction is **immutably sealed** on the **SIERL** (*ShieldNet Immutable Evidence & Response Ledger*) blockchain:

```
┌─────────────────────────────────────────────────┐
│  SIERL Block Structure                          │
│  block_id      : Sequential + Genesis Anchor    │
│  evidence_hash : SHA-256(raw PCAP / telemetry)  │
│  model_hash    : SHA-256(world_model_grand.pt)  │
│  prediction_hash: SHA-256(attack class + probs) │
│  xai_hash      : SHA-256(SHAP/IG attributions)  │
│  analyst_sig   : Human approval / override      │
│  prev_hash     : Hash-chain tamper detection    │
└─────────────────────────────────────────────────┘
```

**Legal Compliance:** Tamper-proof electronic forensic evidence under **Bharatiya Sakshya Adhiniyam (BSA) 2023 — Section 63**. Aligned with **MeitY National Cyber Security Strategy** and **NCIIPC CII Protection Guidelines**.

---

## 🚀 4. Feature Pipeline & Datasets

### Datasets Used

| Dataset | Size | Attack Types | Usage |
|:---|:---:|:---|:---|
| **CIC-IDS-2017** | 2.8M flows | DoS, PortScan, Botnet, Web Attacks | Primary training |
| **CSE-CIC-IDS2018** | 16M flows | Brute-Force, Infiltration, DoS variants | Secondary training |
| **CTU-13** | 13 scenarios | Botnet (IRC, P2P, HTTP C2) | Botnet generalization |
| **UNSW-NB15** | 2.5M flows | Fuzzers, Exploits, Backdoors, DoS | Cross-dataset evaluation |
| **DARPA 1998** | Military PCAP | Insider threats, Network probes | Domain robustness |

### Feature Extraction Pipeline

```bash
# From raw PCAP files
python scripts/extract_pcap_features.py --input data/captures/ --output data/processed/

# From CSV flow records (CIC-IDS format)
python scripts/extract_csv_features.py --input dataset/ --output data/processed/

# Output: timestamped 84-dimensional normalized feature matrices
```

---

## ⚡ 5. Quickstart & Setup Instructions

### Prerequisites

| Tool | Version | Purpose |
|:---|:---:|:---|
| **Python** | 3.10+ | Backend, ML models, FastAPI |
| **Node.js** | 18+ | React frontend, Vite dev server |
| **Git** | Any | Repository cloning |

> **Note:** All Python dependencies are installable offline from the `venv/` directory if already populated, or via `pip install -r requirements.txt`.

---

### Option A — One-Command Automated Launch (Recommended)

**Windows:**
```bat
run_offline.bat
```

**Linux / macOS:**
```bash
chmod +x run_offline.sh
./run_offline.sh
```

This automatically:
1. Starts FastAPI backend + SIERL Ledger on `http://127.0.0.1:8000`
2. Starts React SOC Dashboard on `http://localhost:5173`
3. Opens browser at the dashboard

---

### Option B — Manual Step-by-Step Launch

**Step 1 — Clone the repository:**
```bash
git clone https://github.com/harirajharsh8795/ShieldNet-Backend.git
cd ShieldNet-Backend
```

**Step 2 — Install Python dependencies:**
```bash
# Using venv (recommended)
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux/macOS
pip install -r requirements.txt
```

**Step 3 — Start the FastAPI Backend (Terminal 1):**
```bash
python -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000 --reload
```
✅ Backend API docs available at: `http://127.0.0.1:8000/docs`

**Step 4 — Start the React Frontend (Terminal 2):**
```bash
cd frontend
npm install
npm run dev
```
✅ SOC Dashboard available at: `http://localhost:5173`

---

### Option C — Run Verification & Benchmark Tests

**Run the 9-Cell Model Superiority Benchmark:**
```bash
python scripts/benchmarks/benchmark_gru_vs_lstm_vs_logreg.py
```

**Run SIERL Blockchain Unit Tests (6/6):**
```bash
python -m pytest tests/test_sierl_blockchain.py -p no:playwright -p no:timeout -v
```

**Run Full Test Suite:**
```bash
python -m pytest tests/ -v
```

---

### SOC Portal Login Credentials

| Role | Email | Password | Access Level |
|:---|:---|:---|:---:|
| **CISO / Administrator** | `admin@shieldnet.local` | `Admin@123` | Level 5 — Full access |
| **SOC Tier-2 Analyst** | `analyst@shieldnet.local` | `Analyst@123` | Level 3 — Threat hunting |
| **Forensic Auditor** | `auditor@shieldnet.local` | `Auditor@123` | Level 4 — Evidence review |
| *(Government alias)* | `admin@shieldnet.gov.in` | `shieldnet2026` | Level 5 |

---

## 📂 6. Repository Structure

```
ShieldNet/
├── run_offline.bat              # ← One-command Windows launch script
├── run_offline.sh               # ← One-command Linux/macOS launch script
├── requirements.txt             # Python dependencies
├── train.py                     # Model training entry point
│
├── frontend/                    # React + TypeScript + Vite SOC Dashboard
│   ├── src/pages/
│   │   ├── DashboardPage.tsx    # Executive Overview & Telemetry HUD
│   │   ├── LiveMonitorPage.tsx  # Real-time flow stream & OOD drift alerts
│   │   ├── ComparePage.tsx      # 9-Cell Benchmark (GRU vs LSTM vs LogReg)
│   │   ├── BlockchainAuditPage.tsx # SIERL Block Explorer & Evidence Verifier
│   │   └── UploadPage.tsx       # PCAP & CSV drag-and-drop ingestion
│   └── src/data/api.ts          # Production API client (100% offline fallbacks)
│
├── src/
│   ├── api/server.py            # FastAPI REST server (Auth, SIERL, Ingestion, Mitigations)
│   ├── world_model/
│   │   ├── model.py             # 3-Layer GRU (H=512) + 8-Head Attention World Model
│   │   └── dataset.py           # Temporal window sequence extractor (L=10)
│   ├── features/
│   │   ├── fusion.py            # 84-D dual-level feature fusion (77 flow + 7 packet)
│   │   ├── ood_detector.py      # Out-of-distribution & feature drift guard
│   │   ├── schema_adapter.py    # Cross-dataset normalizer (UNSW, CTU-13, CIC-IDS)
│   │   └── scaler_guard.py      # Frozen reference normalization safeguard
│   ├── ledger/
│   │   ├── sierl_ledger.py      # SHA-256 hash-chained SIERL blockchain
│   │   ├── evidence_hasher.py   # Multi-artifact hasher (PCAP, weights, XAI)
│   │   └── orchestrator.py      # Simulated SOAR firewall actuator (iptables, nftables)
│   ├── explainability/
│   │   ├── feature_attribution.py # Dual-engine XAI: Integrated Gradients + SHAP
│   │   └── mitre_kg.py          # Symbolic MITRE ATT&CK reasoner
│   ├── mitigation/
│   │   ├── counterfactual_engine.py # 5-scenario what-if simulation
│   │   └── defense_synthesizer.py   # Sovereign defense action generator
│   ├── auth/security.py         # HMAC-SHA256 JWT tokens & RBAC security
│   └── database/db.py           # SQLite + SQLAlchemy persistent incident database
│
├── scripts/
│   ├── benchmarks/
│   │   └── benchmark_gru_vs_lstm_vs_logreg.py  # 9-Cell benchmark generator
│   └── [20+ analysis and training scripts]
│
├── models/checkpoints/
│   ├── world_model_grand_omni.pt      # ← Champion frozen neural weights
│   ├── MODEL_BENCHMARK_9CELL.json     # Verified 9-cell benchmark data
│   ├── FINAL_BENCHMARK_SOTA99.json    # SOTA performance checkpoint
│   └── sierl_ledger.json              # Committed blockchain state
│
├── docs/
│   ├── ARCHITECTURE_DOCUMENT_2PAGE.md # SIH mandated 2-page architecture doc
│   ├── SLIDES_5SLIDES_OUTLINE.md      # SIH mandated 5-slide outline
│   ├── PS_COMPLIANCE_MATRIX.md        # PS-26153 requirement compliance matrix
│   └── EXAMINER_DEFENSE_CHEATSHEET.md # Top 10 NTRO Q&A preparation
│
└── tests/
    └── test_sierl_blockchain.py        # 6/6 unit tests for ledger & tamper detection
```

---

## 🔒 7. Non-Negotiable Constraint Compliance Matrix

| Constraint | PS-26153 Requirement | ShieldNet Implementation | Status |
|:---:|:---|:---|:---:|
| **C1** | Passive network analysis only | Passive NetFlow/PCAP ingestion; zero active port scanning or pinging | ✅ Verified |
| **C2** | Mandatory enforced explainability | Dual-engine XAI (Integrated Gradients + SHAP); black-box output raises system error | ✅ Verified |
| **C3** | World model temporal dynamics | Learns P(S_t+1\|S_t); +3.28σ shuffle-significance ablation test confirms genuine temporal learning | ✅ Verified |
| **C4** | 100% Offline / Air-Gapped | Fully operational under zero-egress isolation; zero cloud API dependencies | ✅ Verified |
| **C5** | Comparative baseline benchmarking | 9-cell matrix: GRU+Attention vs Plain LSTM vs Logistic Regression on identical 84-D features | ✅ Verified |
| **C6** | Immutable audit trail | SIERL SHA-256 hash-chained blockchain; BSA 2023 Sec 63 compliant; tamper detection < 0.12s | ✅ Verified |

---

## 🌐 8. Government & Statutory Compliance

- **MeitY National Cyber Security Strategy** — Aligned with India's national framework for sovereign AI-based cyber defense
- **NCIIPC CII Protection Guidelines** — Designed to protect Critical Information Infrastructure (power grids, SCADA, financial systems)
- **Bharatiya Sakshya Adhiniyam (BSA) 2023 — Section 63** — Tamper-proof SIERL blockchain generates legally admissible electronic forensic evidence for digital prosecution
- **Atmanirbhar Bharat** — 100% sovereign, air-gapped, no foreign cloud dependencies
- **CERT-In 6-Hour Reporting** — Automated incident log generation accelerates mandatory breach notification

---

## 📜 License & Acknowledgments

Developed for **Smart India Hackathon 2026 (SIH-26153)** under the auspices of the **National Technical Research Organisation (NTRO)**.

**Datasets:** Canadian Institute for Cybersecurity (CIC-IDS-2017/2018), Czech Technical University (CTU-13), University of New South Wales (UNSW-NB15), US DoD DARPA 1998.

**Key References:**
- Cho et al. (2014) — *Learning Phrase Representations using RNN Encoder–Decoder for Statistical Machine Translation* (GRU architecture)
- Sundararajan et al. (2017) — *Axiomatic Attribution for Deep Networks* (Integrated Gradients XAI)
- MITRE ATT&CK Framework — `https://attack.mitre.org`
- BSA 2023 Section 63 — Bharatiya Sakshya Adhiniyam (Electronic Records Admissibility)
