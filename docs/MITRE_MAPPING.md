# NetGuard — MITRE ATT&CK Stage Mapping Specification

## Overview
This document specifies the defensible mapping logic used by NetGuard to map state-vector dynamics and model predictions to five simplified **MITRE ATT&CK Enterprise Tactic Stages** as required by SIH26153 (NTRO).

---

## 1. Stage Definitions & Tactical Alignment

| Stage ID | Stage Name | MITRE Tactic ID | Primary Indicator Features | CICIDS2017 Ground Truth |
|---|---|---|---|---|
| **0** | **Benign** | N/A | Low SYN/RST ratios, standard TTL variance, balanced flow rates | Benign, Normal, Background |
| **1** | **Reconnaissance** | `TA0043` | `port_scan_sequential_score` > 0.3, `syn_ratio` > 0.5, low payload bytes | PortScan, IP Scan, Sweep |
| **2** | **Initial Access** | `TA0001` | `rst_ratio` > 0.2, short flow durations, high retransmissions | FTP-Patator, SSH-Patator, Web Attack - Brute Force, Web Attack - XSS, SQLi |
| **3** | **Lateral Movement** | `TA0008` | `ttl_variance` > 5.0, internal port hopping, high payload entropy | Infiltration, Internal pivoting |
| **4** | **Command & Control** | `TA0011` | Low IAT std (regular beaconing), high payload entropy (encrypted C2), small packet sizes | Bot, Botnet (Ares, Zeus) |
| **5** | **Exfiltration / Impact** | `TA0010` / `TA0040` | High outbound bytes (`total_fwd_bytes` > 10KB), DoS packet bursts (`flow_packets_per_sec` > 1K) | DoS-Hulk, DoS-Slowloris, DoS-GoldenEye, DoS-Slowhttptest, DDoS-LOIC, Heartbleed |

---

## 2. Cross-Dataset Generalisation Mappings

### A. UNSW-NB15 Taxonomy Mapping:
| UNSW-NB15 Category | Assigned MITRE Stage | Tactical Rationale |
| :--- | :---: | :--- |
| **Normal** | **0 (Benign)** | Uncompromised operational traffic |
| **Reconnaissance** | **1 (Reconnaissance)** | Port scans, address sweeps, OS fingerprinting probes |
| **Fuzzers** | **1 (Reconnaissance)** | Protocol fuzzing and boundary probing before exploitation |
| **Analysis** | **1 (Reconnaissance)** | Vulnerability scanning and web application mapping |
| **Exploits** | **2 (Initial Access)** | Buffer overflows, RCE attempts, and weaponized payload delivery |
| **Generic** | **3 (Lateral Movement)** | Cryptographic payload spraying and unauthorized lateral access |
| **Worms** | **3 (Lateral Movement)** | Self-propagating autonomous network traversal |
| **Backdoor** | **4 (Command & Control)** | Persistent reverse shells and remote access beaconing |
| **DoS** | **5 (Exfiltration / Impact)** | Volumetric and state exhaustion denial of service |

### B. CIC-IDS-2018 Taxonomy Mapping:
| CIC-IDS-2018 Category | Assigned MITRE Stage | Tactical Rationale |
| :--- | :---: | :--- |
| **Benign** | **0 (Benign)** | Standard AWS production traffic |
| **Infiltration** | **3 (Lateral Movement)** | Post-compromise internal reconnaissance and subnet traversal |
| **Botnet (Ares)** | **4 (Command & Control)** | Python Ares botnet master-worker communication |
| **BruteForce (FTP/SSH/Web)** | **2 (Initial Access)** | Automated dictionary authentication attacks |
| **DoS (Hulk, GoldenEye, Slowloris)** | **5 (Impact)** | Application-layer HTTP connection exhaustion |
| **DDoS (LOIC, HOIC)** | **5 (Impact)** | Distributed volumetric flood attacks |

---


## 2. Dual-Signal Decision Engine

NetGuard uses a **hybrid decision engine** combining neural classification logits with domain-rule validation:

$$\text{Score}(\text{Stage}_k) = w_{\text{clf}} \cdot P_{\text{neural}}(\text{Stage}_k) + w_{\text{rule}} \cdot S_{\text{rule}}(\text{Stage}_k)$$

- **Neural Classifier Signal ($w_{\text{clf}} = 0.7$):** Softmax output from the auxiliary classification head of the World Model.
- **Domain Rule Validation ($w_{\text{rule}} = 0.3$):** Threshold checks against predicted state feature values.

If neural classifier confidence exceeds $0.80$, the classifier prediction is trusted directly.

---

## 3. Defense Against Evaluator Scrutiny

- **Question:** *"Why is Botnet categorized as Command & Control and not Lateral Movement?"*
  - **Answer:** Botnet telemetry in CTU-13 / CIC-IDS-2018 is dominated by periodic C2 beaconing (low inter-arrival time standard deviation) and high payload entropy (encrypted C2 channel communication).

- **Question:** *"How do you handle ambiguous state transitions?"*
  - **Answer:** The K-step simulation rollout outputs a continuous probability timeline along with per-step stage predictions and decaying confidence scores ($0.85^k$). If stage transitions occur at step $K=3$, the dashboard highlights the exact step where the transition crosses the alert threshold.
