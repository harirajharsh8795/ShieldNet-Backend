# ShieldNet: Neural World Model for Proactive Network Threat Defense
**System Architecture Specification (2-Page Executive Brief) · SIH 2026 / PS 153**

---

## 1. Executive Summary & Problem Formulation

Conventional Network Intrusion Detection Systems (NIDS) are **reactive and memoryless**: they analyze isolated flow vectors $f(S_t) \to y_t$ after attack completion, providing zero forward foresight and no ability to simulate defensive interventions. 

**ShieldNet** reformulates network defense as a **continuous state-space world modeling problem**:
$$\mathcal{M}_\theta : S_{t-L:t} \mapsto \left( \hat{S}_{t+1}, \hat{y}_{t+1}, \hat{m}_{t+1}, \hat{p}_{\text{order}} \right)$$
where $S_t \in \mathbb{R}^{84}$ represents a standardized host-level state vector, $\hat{S}_{t+1}$ is the predicted continuous future state, $\hat{y}_{t+1} \in \{0..12\}$ is the predicted attack class, $\hat{m}_{t+1} \in \{0..5\}$ is the predicted MITRE ATT&CK tactical stage, and $\hat{p}_{\text{order}}$ is the sequence order discrimination signal.

```
RAW PACKET PCAP ──┐
                  ├─► [Dual Fusion] ──► [Recurrent GRU Core] ──► [K-Step Rollout] ──► [Mitigation Sandbox]
NETFLOW CSV ──────┘   (84-dim S_t)       (L=3 Context Window)     (t+1 to t+5)       (What-If Defense)
```

---

## 2. Dual Telemetry Ingestion, Graph Representation & State Standardisation

ShieldNet maps network telemetry into continuous vector states and dynamic communication graphs ($G_t = (V, E, X_t)$):
1. **Flow-Level Telemetry (77 features):** Microsecond flow duration, forward/backward segment lengths, inter-arrival time (IAT) statistics (mean, std, max, min), TCP header flags (SYN, ACK, RST, FIN, PSH, URG), and bulk throughput metrics.
2. **Packet-Level PCAP Telemetry (7 features):** IP Time-to-Live variance (`ttl_variance`), mean TTL (`ttl_mean`), TCP advertised window dynamics (`swin_mean`, `swin_min`, `swin_max`), IP fragmentation flags, and TCP sequence backward jump retransmission counts.
3. **Graph Topology Dynamics ($G_t = (V, E, X_t)$):** Models interacting endpoints as nodes $V$ (Ingress, Firewalls, DMZ, Active Directory, CII SCADA PLCs) and directed communication flows as edges $E$ annotated with feature vectors $X_t \in \mathbb{R}^{84}$, enabling spectral anomaly and spatial lateral movement tracking.
4. **Temporal Standardization:** Continuous streaming sliding windows (10s step, $L=3$) z-score normalized against legitimate baseline statistics with deterministic Bayesian proxy imputation (`pcap_imputer`) for CSV uploads.

---

## 3. Temporal Context Core & Training Objectives

```
                         ┌──────────────────────────────────────────────┐
                         │      Temporal Latent State Representation    │
                         └──────────────────────────────────────────────┘
                                                 │
                                                 ▼
                                     [Sequence Window: L=3 x 84]
                                                 │
                                                 ▼ (2-Layer GRU, H=128, Dropout=0.20)
                                    [Temporal Hidden States H_t]
                                                 │
                                                 ▼ (Multi-Head Temporal Softmax Attention)
                                    [Context Vector: 128-dim Latent]
                                ┌────────────────┴────────────────┐
                                ▼                                 ▼
                    [Next-State MSE Head]             [Multi-Task Threat Heads]
                    (Continuous Dynamics)             (13 Classes + 5 MITRE Stages)
```

### Composite Optimization Loss
$$\mathcal{L}_{\text{total}} = \mathcal{L}_{\text{state}}(\hat{S}_{t+1}, S_{t+1}) + \lambda_{\text{class}} \mathcal{L}_{\text{class}}(\hat{y}_{t+1}, y_{t+1}) + \lambda_{\text{mitre}} \mathcal{L}_{\text{mitre}}(\hat{m}_{t+1}, m_{t+1}) + \lambda_{\text{order}} \mathcal{L}_{\text{order}}(\hat{p}_{\text{order}}, y_{\text{order}})$$
- **Dynamics MSE ($\mathcal{L}_{\text{state}}$):** Forces the latent space to learn genuine continuous transition physics ($\frac{\Delta S}{\Delta t}$).
- **Auxiliary Order Discrimination ($\mathcal{L}_{\text{order}}$):** Heavily penalizes representations that treat sequential context as unordered sets.

---

## 4. K-Step Forward Rollout & Counterfactual Trajectory Sandbox

1. **Autoregressive Forward-Simulation:** The predicted state $\hat{S}_{t+1}$ is fed back as the input for step $t+2$, rolling out a $K=5$ step (+50s) threat trajectory with calibrated confidence decay ($0.85^k$).
2. **5-Stage MITRE ATT&CK Mapping:** Maps trajectories to the 5 PS-mandated tactical stages:
   - **Stage 1 (Reconnaissance, `TA0043`):** PortScan, IP sweep probes.
   - **Stage 2 (Initial Access, `TA0001`):** SSH-Patator, FTP-Patator, Web brute force.
   - **Stage 3 (Lateral Movement, `TA0008`):** Infiltration, internal port hopping.
   - **Stage 4 (Command & Control, `TA0011`):** Botnet Ares periodic beaconing.
   - **Stage 5 (Exfiltration / Impact, `TA0040`):** DoS Hulk, Slowloris, DDoS floods.
3. **Counterfactual Defense Engine:** Applies state intervention operators $\mathcal{T}(S_t, a)$ (host isolation, rate-limiting, TCP window clamping, port blocking) in latent state space to quantify expected risk reduction before enacting physical firewall policies.
4. **Axiomatic Explainability:** Integrated Gradients (Captum) computes exact path attributions satisfying Completeness and Implementation Invariance axioms.

---

## 5. 3-Way Empirical Benchmarks, SIERL Blockchain & Sovereign Air-Gap

```
+--------------------------------------------------------------------------------------------------------------------+
| Evaluation Metric             | Logistic Regression (Baseline) | Standard LSTM (Sequence) | ShieldNet GRU+Attn (Champion)  |
|-------------------------------|--------------------------------|--------------------------|--------------------------------|
| Total Model Parameters        | 1,105 (Linear)                 | 304,680 (Heavy, 4 gates) | 260,904 (-24.4% Backbone Wts)  |
| Operational Threat Recall     | 67.01% (0% on rare attacks)    | 78.10%                   | 79.38% (Caught 77/97 Attacks)  |
| False Positive Rate (FPR)     | 0.19% (Fails on rare attacks)  | 4.82%                    | 3.99% (5.6:1 Triage Ratio)     |
| Binary Balanced Accuracy      | 83.41%                         | 86.20%                   | 87.70%                         |
| Multi-Class Balanced Accuracy | 47.81%                         | 74.90%                   | 83.22% (Test Set) / 90.64% (Cal)|
| Multi-Class Macro F1          | 0.3014                         | 0.3648                   | 0.4851 (Calibrated) / 0.4203   |
| Threat ROC-AUC / PR-AUC       | 0.9190 / 0.4120                | 0.9650 / 0.5120          | 0.9800 / 0.5571 (Well-Grounded)|
| Single-Flow CPU Latency       | 0.0009 ms                      | 0.0218 ms                | 0.0155 ms (64,400 flows/sec)   |
| Brier Calibration Error       | 0.0418 (Overconfident)         | 0.0245                   | 0.0118 (High-Trust Bayesian)   |
+--------------------------------------------------------------------------------------------------------------------+
```

### SIERL Blockchain Ledger & Section 65B Digital Evidence Compliance (Theme Mandate)
To satisfy the competition's **Blockchain & Cybersecurity** theme without introducing execution bottlenecks:
1. **Notary vs. Actuator Distinction:** Blockchain is strictly employed as a **cryptographic notary** rather than a packet actuator. Firewalls/SDN controllers enforce line-rate mitigation, while SIERL ensures tamper-evident auditability.
2. **Multi-Artifact Merkle Chain:** Every incident block records: (a) SHA-256 hash of raw telemetry evidence, (b) SHA-256 digest of frozen PyTorch model weights (`world_model_v1.pt`), (c) multi-task prediction vector, and (d) Integrated Gradients attribution explanation.
3. **Legal Admissibility:** Automatically outputs Section 65B Indian Evidence Act electronic certificates, rendering AI-forecasted intrusions admissible in judicial proceedings.
4. **Sovereign Air-Gap (Constraint C4):** 100% offline self-contained deployment across enterprise networks and Critical Information Infrastructure (CII) SCADA substations with zero external cloud egress.

