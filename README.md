# 🛡️ ShieldNet — World-Model Network-Attack-Forecasting System

> **Smart India Hackathon 2026 — Problem Statement SIH26153**  
> **Organization:** National Technical Research Organisation (NTRO)  
> **Theme:** Blockchain & Cybersecurity  

ShieldNet is a submission-ready network security prototype that learns computer network temporal state transitions ($P(S_{t+1} \mid S_t)$) from traffic telemetry to predict the likelihood and progression of malicious activity **before compromise is completed**.

---

## 🌟 Key Capabilities & PS Alignment

- **Dual-Level Telemetry Ingestion:** Ingests both **Flow-Level** (80+ metrics: durations, byte/packet rates, bidirectional IAT) and **Packet-Level** (TTL variance, TCP window std, IP fragment flags, payload entropy, port-scan scores) features.
- **Generative World Models Paradigm:** Learns state transition dynamics $P(S_{t+1} \mid S_t)$ using a PyTorch 2-layer stacked LSTM sequence model.
- **Autoregressive K-Step Simulation:** Projects network state trajectories up to $K=50$ steps into the future, yielding a continuous infiltration probability timeline with decaying confidence scores ($0.85^k$).
- **5-Stage MITRE ATT&CK Mapping:** Maps predicted future states to *Reconnaissance (TA0043)*, *Initial Access (TA0001)*, *Lateral Movement (TA0008)*, *Command & Control (TA0011)*, and *Exfiltration (TA0010)*.
- **Mandatory Enforced Explainability (Constraint C2):** Every forecast ships with SHAP / gradient attributions and natural language summaries; code raises `ExplanationMissingError` if an explanation object is absent.
- **100% Offline Operation (Constraint C4):** Streamlit GUI and CLI run with zero cloud/API network calls.
- **Baseline Benchmarking (Constraint C5):** Evaluates performance vs a Logistic Regression baseline on identical features.

---

## 📂 Repository Deliverables Index

- **Source Code:** [`src/`](file:///e:/Desktop/ps%20153/shieldnet/src/)
  - Ingestion: [`src/ingestion/loader.py`](file:///e:/Desktop/ps%20153/shieldnet/src/ingestion/loader.py)
  - Schema & Features: [`src/features/schema.py`](file:///e:/Desktop/ps%20153/shieldnet/src/features/schema.py), [`src/features/packet_level.py`](file:///e:/Desktop/ps%20153/shieldnet/src/features/packet_level.py), [`src/features/sequencer.py`](file:///e:/Desktop/ps%20153/shieldnet/src/features/sequencer.py)
  - World Model Engine: [`src/world_model/model.py`](file:///e:/Desktop/ps%20153/shieldnet/src/world_model/model.py), [`src/world_model/trainer.py`](file:///e:/Desktop/ps%20153/shieldnet/src/world_model/trainer.py)
  - K-Step Simulator: [`src/simulation/rollout.py`](file:///e:/Desktop/ps%20153/shieldnet/src/simulation/rollout.py), [`src/simulation/mitre_mapping.py`](file:///e:/Desktop/ps%20153/shieldnet/src/simulation/mitre_mapping.py)
  - Explainability: [`src/explainability/explain.py`](file:///e:/Desktop/ps%20153/shieldnet/src/explainability/explain.py)
  - Baseline & Evaluation: [`src/baseline/baseline_model.py`](file:///e:/Desktop/ps%20153/shieldnet/src/baseline/baseline_model.py), [`src/evaluation/evaluate.py`](file:///e:/Desktop/ps%20153/shieldnet/src/evaluation/evaluate.py)
  - Dashboard: [`src/dashboard/app.py`](file:///e:/Desktop/ps%20153/shieldnet/src/dashboard/app.py)
- **Architecture Document (max 2 pages):** [`docs/ARCHITECTURE.md`](file:///e:/Desktop/ps%20153/shieldnet/docs/ARCHITECTURE.md)
- **Technical Presentation Outline (max 5 slides):** [`docs/slides_outline.md`](file:///e:/Desktop/ps%20153/shieldnet/docs/slides_outline.md)
- **Demo Video Script (max 2 minutes):** [`docs/demo_video_script.md`](file:///e:/Desktop/ps%20153/shieldnet/docs/demo_video_script.md)
- **MITRE Mapping Specification:** [`docs/MITRE_MAPPING.md`](file:///e:/Desktop/ps%20153/shieldnet/docs/MITRE_MAPPING.md)
- **Phase Exit Reports:** [`docs/phase_reports/`](file:///e:/Desktop/ps%20153/shieldnet/docs/phase_reports/)

---

## 🚀 Quickstart Guide

### 1. Environment Setup
```bash
# Activate python environment
cd shieldnet
python -m venv venv
# On Windows:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Dataset Setup
Download **CIC-IDS-2018** and/or **CTU-13** CSV files and place them into the respective directories:
- `data/raw/cic-ids-2018/`
- `data/raw/ctu-13/`

*Refer to [`docs/DATASET_SETUP.md`](file:///e:/Desktop/ps%20153/shieldnet/docs/DATASET_SETUP.md) for full instructions.*

To verify dataset integrity and generate file manifests:
```bash
python scripts/verify_datasets.py
```

### 3. Run Training & Evaluation Pipeline
```bash
python scripts/run_pipeline.py
```

### 4. Prove World Model Dynamics Learning (Constraint C3)
```bash
python scripts/prove_world_model.py
```

### 5. Launch Offline Streamlit Dashboard
```bash
streamlit run src/dashboard/app.py
```

---

## 🧪 Unit Tests

Run full test suite:
```bash
pytest tests/ -v
```

---

## 📋 Non-Negotiable Constraint Compliance Matrix

| Constraint | Description | Compliance Status |
|---|---|---|
| **C1** | Passive analysis only | **PASSED** (Inference is 100% passive) |
| **C2** | Mandatory explainability | **PASSED** (Enforced via `ExplanationMissingError`) |
| **C3** | Dynamics learning proof | **PASSED** (`scripts/prove_world_model.py` verified) |
| **C4** | Zero cloud calls | **PASSED** (Offline operation verified) |
| **C5** | Benchmark vs Logistic Regression | **PASSED** (Baseline evaluated on identical split) |
| **C6** | Reproducibility | **PASSED** (Fixed seeds & pinned requirements) |
| **C7** | CIC-IDS-2018 & CTU-13 alignment | **PASSED** (Unified schema + cross-eval script) |
| **C8** | Format limits (Doc ≤ 2 pages, Video ≤ 2m, Slides ≤ 5) | **PASSED** (All 3 deliverables strictly within limits) |
