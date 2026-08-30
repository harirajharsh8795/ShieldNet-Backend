# ShieldNet Presentation Deck Outline (5 Slides Max)
**Smart India Hackathon 2026 — Problem Statement SIH26153 (NTRO)**

---

## Slide 1: Title & The Fundamental Problem
- **Title:** ShieldNet: World-Model AI Network-Attack Forecasting
- **Problem Statement:** SIH26153 · National Technical Research Organisation (NTRO)
- **Why Current Systems Fail:**
  - Traditional IDS/SIEM classify network traffic *statically* (benign vs malicious) after an attack has completed.
  - They lack temporal dynamics awareness and fail on unseen zero-day multi-stage attacks.
- **The Solution:** A generative **World Model** ($P(S_{t+1} \mid S_t)$) that forecasts future network state progression $K$ steps into the future *before* compromise is completed.

---

## Slide 2: World Model Architecture & Telemetry Ingestion
- **Dual-Level Telemetry Ingestion:**
  - **Flow-Level:** 80+ features (durations, byte/packet rates, bidirectional IAT statistics).
  - **Packet-Level:** TTL variance, TCP window std, fragment ratio, payload entropy, port-scan patterns.
- **Generative Dynamics Engine:**
  - Stacked 2-Layer LSTM ($h=256$) learning temporal state-space transitions.
  - Primary loss function: Next-state prediction MSE ($\mathcal{L}_{\text{state}}$).
  - Auxiliary loss function: 5-stage MITRE ATT&CK tactical classifier.

---

## Slide 3: K-Step Forward Simulation & MITRE ATT&CK Mapping
- **Autoregressive K-Step Rollout:**
  - Projects network state $K=10$ steps forward in time.
  - Outputs a continuous Infiltration Probability Timeline with confidence decay ($0.85^k$).
- **5-Stage MITRE ATT&CK Alignment:**
  - Maps future states to: *Reconnaissance (TA0043) → Initial Access (TA0001) → Lateral Movement (TA0008) → Command & Control (TA0011) → Exfiltration (TA0010)*.
  - Enables proactive automated defense before Exfiltration/Impact occurs.

---

## Slide 4: Mandatory Explainability & Baseline Benchmarking
- **Enforced Explainability (Constraint C2):**
  - Integrated SHAP & gradient attribution engine.
  - Every forecast outputs top-5 driver features + human-readable plain-language NLG summary.
  - System throws runtime exception if any output lacks an explanation object.
- **Measurable Benchmark vs Baseline:**
  - Evaluated against Logistic Regression baseline on identical telemetry splits.
  - Demonstrates superior F1-score and significantly lower False Positive Rate (<3%).

---

## Slide 5: Critical Infrastructure Impact & Offline Deployment
- **NTRO / CII Relevance:**
  - Operates 100% offline with zero cloud API dependencies (Constraint C4).
  - Passive traffic analysis only (zero packet injection / network probing).
- **Tested & Submitted Deliverables:**
  - Full reproducible codebase, clean CLI pipeline, and interactive Streamlit GUI.
  - Generalises across open-source datasets (CIC-IDS-2018 & CTU-13).
