# ShieldNet — Comprehensive Benchmark & Evaluation Report

**Target PS:** SIH26153 (NTRO) — *AI-Based Network Attack Forecasting from Network Traffic Data*  
**Evaluation Role:** Forensic ML Evaluation Auditor  
**Date:** August 30, 2026  
**Locked Submission Model:** `models/checkpoints/world_model_v1.pt` (Single-Scale $L=3$ GRU World Model, SHA-256: `dfbbb33026dec5b640a933400eecad2feb0b3329fb3fb8159e42d34548604371`)  
**Ground Truth Source File:** [`models/checkpoints/GROUND_TRUTH_FINAL.json`](file:///e:/Desktop/ps%20153/shieldnet/models/checkpoints/GROUND_TRUTH_FINAL.json)

---

## 1. Executive Summary & Core Evaluation Findings

ShieldNet was evaluated under verified experimental protocols directly addressing the official SIH26153 evaluation criteria:

1. **Measurable Improvement over Memoryless Baseline (Constraint C5 & R7):**
   - **Balanced Accuracy:** ShieldNet World Model achieves **79.15%** vs. Logistic Regression **50.12%** ($\mathbf{+29.03\%}$ absolute improvement).
   - **Multi-Class Macro F1:** ShieldNet achieves **0.2926** vs. Logistic Regression **0.0652** ($\mathbf{+0.2274}$ / $\mathbf{4.5\times}$ relative boost).
   - **Threat Detection ROC-AUC:** ShieldNet achieves **0.9798** vs. Logistic Regression **0.5764** ($\mathbf{+0.4034}$ gain).
   - **Overall Classification Accuracy:** ShieldNet achieves **89.50%** vs. Logistic Regression **81.35%** ($\mathbf{+8.15\%}$ gain).
   - **Weighted F1-Score:** ShieldNet achieves **0.9377** vs. Logistic Regression **0.8402** ($\mathbf{+0.0975}$ gain).

2. **Temporal Dynamics Verification (Constraint C1 & R2):**
   - 5-seed shuffle permutation ablation proves that scrambling temporal sequence ordering degrades Balanced Accuracy from **79.15%** to a mean of **68.93%** ($\mathbf{-10.22\%}$ drop, $\mathbf{+3.28\sigma}$ significance), verifying genuine temporal dynamics learning $P(S_{t+1} \mid S_t, \dots, S_{t-k})$ over memoryless static classification.

3. **Sub-100ms Inference & Rollout Latency:**
   - Single-step inference latency: **2.10 ms** on standard CPU.
   - 5-step autoregressive rollout latency: **15.21 ms** (mean of 200 benchmark runs).

---

## 2. Side-by-Side Model Benchmark (Locked Submission Baseline)

Both the Logistic Regression Baseline and the ShieldNet World Model (`world_model_v1.pt`) were evaluated on the **exact same held-out test distribution** ($N = 10,909$ sequential state transitions, standardized 84-dimensional state vectors):

| Evaluation Metric | Simple Baseline (Logistic Regression) | ShieldNet World Model (`world_model_v1.pt`) | ShieldNet Gain ($\Delta$) | Verification Protocol & Support |
| :--- | :---: | :---: | :---: | :--- |
| **Multi-Class Macro F1** | 0.0652 | **0.2926** | **+0.2274** ($4.5\times$) | Argmax on 13-class test set ($N = 10,909$) |
| **Balanced Accuracy** | 50.12% | **79.15%** | **+29.03%** gain | Arithmetic mean of per-class recalls ($N = 10,909$) |
| **Overall Classification Accuracy** | 81.35% | **89.50%** | **+8.15%** gain | Total correct transitions ($N = 10,909$) |
| **Overall Weighted F1-Score** | 0.8402 | **0.9377** | **+0.0975** gain | Class-weighted test harmonic mean ($N = 10,909$) |
| **Threat Detection ROC-AUC** | 0.5764 | **0.9798** | **+0.4034** area | Binary attack vs benign discrimination ($N = 10,909$) |
| **Temporal Shuffle Significance** | 0.00 $\sigma$ | **+3.28 $\sigma$** | **+10.22%** delta | 5-seed shuffle permutation test ($N = 10,909$) |
| **K=5 Step Rollout Latency** | N/A (Static) | **15.21 ms** | **Real-time** | Autoregressive forward projection on CPU |

---

## 3. Per-Class Test Performance Breakdown (Paired with Exact Test Support $N$)

Evaluated across all 13 canonical network traffic classes on held-out test transitions ($N = 10,909$ total):

| Attack Class | Category | Test Support ($N$) | Precision | Recall | F1-Score | Status / Observation |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **BENIGN** | Background Baseline | $N = 10,812$ | **0.9995** | 0.8953 | **0.9445** | Robust high-volume baseline |
| **Bot** | Periodic C2 Beacon | $N = 51$ | 0.0556 | **0.9216** | 0.1049 | 92.2% of bot beacons intercepted |
| **DDoS** | Volumetric LOIC Flood | $N = 3$ | **0.6000** | **1.0000** | **0.7500** | 3/3 flood transitions intercepted |
| **DoS GoldenEye** | HTTP KeepAlive Flood | $N = 1$ | 0.0588 | **1.0000** | 0.1111 | 1/1 transition caught |
| **DoS Hulk** | HTTP Exhaustion Flood | $N = 3$ | 0.1538 | 0.6667 | 0.2500 | 2/3 flood transitions intercepted |
| **DoS Slowhttptest** | Slow Request Flood | $N = 3$ | 0.0000 | 0.0000 | 0.0000 | Subsumed by adjacent DoS states |
| **DoS slowloris** | Connection Hold Flood | $N = 4$ | 0.0508 | **0.7500** | 0.0952 | 3/4 connection holds intercepted |
| **FTP-Patator** | Auth Brute Force | $N = 9$ | 0.1127 | **0.8889** | 0.2000 | 8/9 brute-force attempts caught |
| **PortScan** | Reconnaissance Sweep | $N = 2$ | 0.1538 | **1.0000** | 0.2667 | 2/2 reconnaissance sweeps intercepted |
| **Rare-Attack** | Infiltration / Exploit | $N = 3$ | 0.0357 | 0.6667 | 0.0678 | 2/3 hard negative anomalies caught |
| **SSH-Patator** | SSH Brute Force | $N = 9$ | 0.0978 | **1.0000** | 0.1782 | 9/9 SSH brute-force attempts caught |
| **Web Attack - Brute Force** | Web Credential Guessing | $N = 6$ | 0.2941 | **0.8333** | **0.4348** | 5/6 web exploit attempts caught |
| **Web Attack - XSS** | Cross-Site Scripting | $N = 3$ | 0.2857 | 0.6667 | 0.4000 | 2/3 XSS attack sequences caught |

---

## 4. Cross-Dataset Generalization Empirical Findings

Source File: [`models/checkpoints/GROUND_TRUTH_CROSS_DATASET.json`](file:///e:/Desktop/ps%20153/shieldnet/models/checkpoints/GROUND_TRUTH_CROSS_DATASET.json)

| Dataset | Evaluated Sequences | Matched Features | ROC-AUC | Macro-F1 | Empirical Finding |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **UNSW-NB15** | $N = 20,000$ | 0 / 77 | 0.5000 | 0.0119 | Feature column names differ between datasets; zero-shot transfer without schema alignment produces random-chance baseline. |
| **CSE-CIC-IDS2018** | $N = 19,998$ | 77 / 77 | 0.0361 | 0.1478 | Direct transfer across differing infrastructure without distribution recalibration degrades ranking. |

**Technical Takeaway:** Supervised state representations are tightly coupled to the exact statistical normalization parameters of the training domain. Domain adaptation or schema alignment is required for seamless cross-enterprise transfer.
