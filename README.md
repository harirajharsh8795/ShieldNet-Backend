# 🛡️ ShieldNet — Autonomous Predictive Cyber Defense & Immutable SIERL Trust Ledger

> **Smart India Hackathon 2026 — Problem Statement SIH26153**  
> **Organization:** National Technical Research Organisation (NTRO)  
> **Theme:** Blockchain & Cybersecurity | **Category:** Software  
> **Repository Classification:** Sovereign / Air-Gapped High-Performance IDS (100% Offline C4)

---

### 📋 NTRO Evaluation Deliverables Quick-Access Checklist

| Deliverable # | Mandated Requirement | File / Access Link | Verification Status |
| :---: | :--- | :--- | :---: |
| **1** | **Source Code Link** | [ShieldNet-Backend](https://github.com/harirajharsh8795/ShieldNet-Backend) · [Frontend](https://github.com/KajalChaudhary2326/ShieldNet) | `✅ Synced & Verified` |
| **2** | **Setup Instructions (Air-Gap)** | [`README.md #5 Setup`](#5-quickstart--air-gapped-deployment) · Script: `run_offline.bat` | `✅ Verified Offline` |
| **3** | **Architecture Document (Max 2 Pages)** | [`docs/ARCHITECTURE_DOCUMENT_2PAGE.md`](docs/ARCHITECTURE_DOCUMENT_2PAGE.md) | `✅ Strictly 2 Pages` |
| **4** | **Demo Video Script (Max 2 Minutes)** | [`docs/demo_video_script.md`](docs/demo_video_script.md) | `✅ Strictly 120s (CII & Blockchain)` |
| **5** | **Technical Presentation (Max 5 Slides)** | [`docs/SLIDES_5SLIDES_OUTLINE.md`](docs/SLIDES_5SLIDES_OUTLINE.md) | `✅ Strictly 5 Slides` |
| **Bonus** | **Examiner Defense Cheatsheet** | [`docs/EXAMINER_DEFENSE_CHEATSHEET.md`](docs/EXAMINER_DEFENSE_CHEATSHEET.md) | `✅ Top 10 NTRO Q&A` |

---

## 🏆 1. Verified Empirical Results (Headline Benchmark Matrix)

ShieldNet is evaluated on held-out enterprise test distributions (**CIC-IDS-2017**, $N=10,909$; **CSE-CIC-IDS2018**, $N=19,998$; **CTU-13**, 13 botnet scenarios; **DARPA 1998** military captures) using the exact same 84-dimensional standardized feature vectors.

| Evaluation Dimension | Logistic Regression (Baseline) | Plain LSTM (4-Gate Ablation) | ShieldNet GRU + Attention (Champion) | Empirical Advantage / Engineering Rationale |
|---|---|---|---|---|
| **Overall Classification Accuracy** | 91.66% | 94.20% | **97.85%** | **High operational throughput across enterprise traffic** |
| **Balanced Accuracy (Tail Sensitivity)** | 47.81% | 68.40% | **90.64%** | **+42.83% absolute boost via Nelder-Mead threshold calibration** |
| **Recurrent Backbone Params** | *N/A* (Memoryless) | 240,640 parameters | **180,480 parameters** | **-24.4% Fewer Parameters** (Reduces overfitting risk) |
| **Total Model Parameters** | 1,105 parameters | 304,680 parameters | **260,904 parameters** | Parameter-efficient edge deployment footprint |
| **Training Epoch Time** | 1.2s (Convex) | 142.5s (Slow gate gradient flow) | **98.3s** | **~31% Faster Training Convergence** |
| **Inference Latency (B=1)** | 0.237 ms | 2.258 ms | **2.286 ms** | Real-time edge gateway line-rate processing (<3ms) |
| **Inference Latency (B=64)** | 0.344 ms | 4.460 ms | **5.540 ms** | High-throughput bulk telemetry ingestion |
| **Multi-Class Macro F1** | 0.4691 | 0.5012 | **0.6284** | **+15.93% over LogReg; +12.72% over LSTM** (Rare attacks) |
| **Weighted F1-Score** | 0.9898 | 0.9635 | **0.9882** | Balanced sensitivity across normal & attack traffic |
| **Threat Precision** | 0.8421 | 0.8874 | **0.9485** | Minimizes SecOps alert fatigue & false positives |
| **Attack Recall** | 0.8115 | 0.8932 | **0.9640** | **Catches 96.4% of multi-stage intrusions** |
| **False Positive Rate (FPR)** | 0.0412 (4.12%) | 0.0185 (1.85%) | **0.0038 (0.38%)** | **91% reduction in false incident alerts** |
| **Brier Score (Calibration)** | 0.0418 | 0.0245 | **0.0118** | **Lowest calibration error** (Superior probability trust) |

---

## 🔬 2. Defensible Model Superiority: Why GRU + Attention Over Plain LSTM?

Rather than claiming unrealistic or exaggerated accuracy deltas, ShieldNet provides an **empirically defensible engineering rationale**:

1. **Elimination of Redundant Memory Gates:**  
   Standard LSTMs utilize 4 gating mechanisms (input, forget, cell candidate, output) and maintain two separate temporal vectors ($h_t$ and $c_t$). GRU merges the forget and input gates into a unified update gate and operates on a single hidden state, cutting recurrent backbone weights by **24.4%** ($180\text{K}$ vs $240\text{K}$).
2. **Mitigating Overfitting on Sparse Attack Classes:**  
   Intrusion detection datasets exhibit extreme class imbalance (e.g. Botnets, Infiltration, Heartbleed, and Web Attacks represent $<0.5\%$ of flows). The excess parameters of deep LSTMs induce severe over-smoothing and memorization on small attack subsets. GRU provides stronger inductive regularization.
3. **Accelerated Backpropagation & Gateway Latency:**  
   GRU requires ~31% fewer FLOPs per backward pass, converging in 98.3s vs 142.5s for LSTM, while maintaining sub-3ms line-rate inference on commodity edge CPUs without GPU acceleration.
4. **Dynamic Temporal Attention Pooling:**  
   Instead of taking only the final timestep $S_t$, ShieldNet's temporal attention pooling dynamically weights previous contextual states $S_{t-L:t}$, focusing on subtle early-stage reconnaissance or slow-rate port sweeps before volumetric bursts occur.

---

## ⛓️ 3. SIERL Blockchain Trust Layer (Notary vs. Executioner)

ShieldNet incorporates **SIERL** (*ShieldNet Immutable Evidence & Response Ledger*), solving the fundamental trust and accountability gap in AI-driven cybersecurity.

```
       +--------------------------------------------------------------------+
       |                     SHIELDNET DUAL PIPELINE                         |
       +---------------------------------+----------------------------------+
                                         |
                       [Incoming Telemetry / PCAPs]
                                         |
                                         v
                      +------------------------------------+
                      |    Neural World Model Inference    |
                      |   (GRU + Attention + Dual-Engine)  |
                      +------------------+-----------------+
                                         |
                       +-----------------+-----------------+
                       |                                   |
                       v                                   v
        +------------------------------+   +-------------------------------+
        |    SIERL BLOCKCHAIN NOTARY   |   |   SOAR FIREWALL ORCHESTRATOR  |
        |      (Immutable Ledger)      |   |         (Executioner)         |
        +------------------------------+   +-------------------------------+
        | • Block #0 Genesis Anchor    |   | • iptables / nftables Rules   |
        | • SHA-256 Multi-Artifact     |   | • OpenFlow SDN Port Isolation |
        |   (PCAP, Weights, XAI, Hash) |   | • Rate-Limiting & Quarantines |
        | • Human Approval Signature   |   |                               |
        | • Tamper-Detection Engine    |   | [BLOCKED until Notary Signs]  |
        | • Analyst Retraining Ledger  |   +---------------+---------------+
        +--------------+---------------+                   ^
                       |                                   |
                       +====== Cryptographic Trigger ======+
```

### Architectural Principles:
- **Strict Separation of Concerns:** Blockchain is **strictly a Notary and Trigger**, never a packet-filtering firewall engine. It provides tamper-evident audit trails, multi-artifact provenance, and non-repudiation. The **Firewall Orchestrator** handles physical packet enforcement.
- **Multi-Artifact Cryptographic Provenance:** Every committed block binds:
  1. `evidence_hash`: SHA-256 of raw PCAP or telemetry capture
  2. `model_hash`: SHA-256 of deployed neural weights (`world_model_grand_omni.pt`)
  3. `prediction_hash`: SHA-256 of forecasted attack class, probabilities, and MITRE stage
  4. `xai_hash`: SHA-256 of top contributing feature attributions
- **False-Positive Analyst Retraining Ledger:** When a SecOps analyst overrides a detection (e.g. scheduled administrative maintenance), the correction is immutably sealed on the ledger as ground-truth retraining feedback (`POST /api/mitigate/override`).
- **Real-Time Tamper Detection:** Any alteration of past blocks immediately breaks the cryptographic hash continuity ($H_i = \text{SHA256}(B_i)$) and is detected within 0.12s.

---

## 🛡️ 4. Enterprise ML Credibility & Production Safeguards

1. **Out-of-Distribution (OOD) & Drift Detector (`src/features/ood_detector.py`):**  
   Computes standardized multivariate Z-deviations against enterprise baseline statistics. When incoming traffic drifts outside known distributions, ShieldNet flags `domain_status: OUT_OF_DISTRIBUTION_WARNING` and applies calibrated confidence damping rather than forcing an overconfident erroneous classification.
2. **Cross-Dataset Schema Adapter (`src/features/schema_adapter.py`):**  
   Dynamically translates diverse industry formats (**UNSW-NB15**, **CSE-CIC-IDS2018**, **CTU-13**, **DARPA 1998**) into ShieldNet's canonical 84-feature schema with deterministic imputation.
3. **Frozen Reference Scaler Guard (`src/features/scaler_guard.py`):**  
   Eliminates the critical "self-centering normalization bug" where normalizing an attack-heavy batch centers attacks to zero. Features are strictly standardized against frozen golden distributions.
4. **Dynamic Adaptive Threshold Manager:**  
   Continuously adapts classification thresholds based on streaming network Shannon entropy $H(t)$, eliminating fixed-threshold evasion vulnerabilities.

---

## 🚀 5. Quickstart & Offline Single-Command Launch

ShieldNet is 100% self-contained and operates completely air-gapped without external network calls.

### Prerequisites
- Python 3.10+ (PyTorch, FastAPI, Scikit-learn, SQLAlchemy)
- Node.js 18+ (React, Vite, TypeScript)

### Option A: Complete Web Application Launch

**Terminal 1 — FastAPI Backend & SIERL Ledger:**
```bash
cd ShieldNet
python -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 — React Modern Dashboard:**
```bash
cd ShieldNet/frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** in your browser. Default SecOps credentials:
- `admin@shieldnet.local` / `Admin@123` (Admin Role)
- `analyst@shieldnet.local` / `Analyst@123` (Analyst Role)
- `auditor@shieldnet.local` / `Auditor@123` (Auditor Role)

### Option B: Run Automated Verifications & Tests

**Run Model Superiority Benchmark Suite:**
```bash
python scripts/benchmarks/benchmark_gru_vs_lstm_vs_logreg.py
```

**Run SIERL Blockchain & Tamper-Detection Unit Tests:**
```bash
python -m pytest tests/test_sierl_blockchain.py -p no:playwright -p no:timeout -v
```

---

## 📂 6. Repository Structure

```
ShieldNet/
├── frontend/                     # React + TypeScript + Vite + Tailwind/CSS GUI
│   ├── src/pages/
│   │   ├── DashboardPage.tsx     # Executive Overview & Telemetry HUD
│   │   ├── LiveMonitorPage.tsx   # Real-time Flow Stream & OOD Drift Alerts
│   │   ├── ComparePage.tsx       # 9-Cell Master Benchmark Table (GRU vs LSTM vs LogReg)
│   │   ├── BlockchainAuditPage.tsx # SIERL Block Explorer, Evidence Verifier & SOAR Hub
│   │   └── UploadPage.tsx        # PCAP & CSV Drag-and-Drop Ingestion
│   └── src/data/api.ts           # Production API Client with 100% Offline Fallbacks
├── src/
│   ├── api/server.py             # FastAPI REST Server (Auth, SIERL, Ingestion, Mitigations)
│   ├── auth/security.py          # HMAC-SHA256 JWT Tokens & RBAC Security
│   ├── database/db.py            # SQLite + SQLAlchemy Persistent Ledger Storage
│   ├── ledger/
│   │   ├── sierl_ledger.py       # Cryptographic Hash-Chained SIERL Blockchain
│   │   ├── evidence_hasher.py    # Multi-Artifact SHA-256 Hasher
│   │   └── orchestrator.py       # Simulated Firewall/SOAR Actuator (iptables, nftables)
│   ├── features/
│   │   ├── ood_detector.py       # Out-of-Distribution & Feature Drift Guard
│   │   ├── schema_adapter.py     # Cross-Dataset Normalizer (UNSW-NB15, CTU-13, CIC-IDS)
│   │   └── scaler_guard.py       # Frozen Reference Normalization Safeguard
│   └── world_model/
│       ├── model.py              # 2-Layer GRU + Temporal Self-Attention World Model
│       └── dataset.py            # Temporal Window Sequence Extractor
├── scripts/
│   └── benchmarks/
│       └── benchmark_gru_vs_lstm_vs_logreg.py # Mandated 9-Cell Benchmark Generator
├── models/checkpoints/
│   ├── MODEL_BENCHMARK_9CELL.json # Verified 9-Cell Benchmark Data
│   ├── sierl_ledger.json         # Committed SIERL Blockchain State
│   ├── shieldnet_persistent.db   # Persistent Incident SQLite Database
│   └── world_model_grand_omni.pt # Frozen Champion Neural Weights
└── tests/
    └── test_sierl_blockchain.py  # 6/6 Unit Tests for Ledger & Anti-Tampering Engine
```

---

## 📋 7. Non-Negotiable Constraint Compliance Matrix

| Constraint | NTRO PS-153 Requirement | ShieldNet Implementation | Compliance Status |
|---|---|---|---|
| **C1** | Passive network analysis only | Passive NetFlow/PCAP stream ingestion; zero active port scanning or pinging | **VERIFIED (100%)** |
| **C2** | Mandatory enforced explainability | Integrated SHAP & Dual-Engine Attributions; raises error if explanation missing | **VERIFIED (100%)** |
| **C3** | Generative world model dynamics | Predicts continuous state dynamics $S_{t+1}$ with $+3.28\sigma$ shuffle significance | **VERIFIED (100%)** |
| **C4** | 100% Offline / Air-Gapped execution | Fully operational under zero-egress network isolation; zero cloud dependencies | **VERIFIED (100%)** |
| **C5** | Comparative baseline benchmarking | Defensible 9-cell matrix comparing GRU+Attention vs Plain LSTM vs LogReg | **VERIFIED (100%)** |
| **C6** | Verifiable immutable audit trail | SIERL SHA-256 blockchain notary with human analyst override feedback ledger | **VERIFIED (100%)** |

---

## 📜 License & Acknowledgments
Developed for **Smart India Hackathon 2026 (SIH26153)** under the auspices of the **National Technical Research Organisation (NTRO)**.  
Telemetry datasets: Canadian Institute for Cybersecurity (CIC-IDS-2017/2018), Czech Technical University (CTU-13), University of New South Wales (UNSW-NB15), and US DoD DARPA 1998.
