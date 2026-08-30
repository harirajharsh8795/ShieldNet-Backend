# NetGuard: Neural World Model for Proactive Network Threat Defense
**System Architecture Specification (2-Page Executive Brief) · SIH 2026 / PS 153**

---

## 1. Executive Summary & Problem Formulation

Conventional Network Intrusion Detection Systems (NIDS) are **reactive and memoryless**: they analyze isolated flow vectors $f(S_t) \to y_t$ after attack completion, providing zero forward foresight and no ability to simulate defensive interventions. 

**NetGuard** reformulates network defense as a **continuous state-space world modeling problem**:
$$\mathcal{M}_\theta : S_{t-L:t} \mapsto \left( \hat{S}_{t+1}, \hat{y}_{t+1}, \hat{m}_{t+1}, \hat{p}_{\text{order}} \right)$$
where $S_t \in \mathbb{R}^{84}$ represents a standardized host-level state vector, $\hat{S}_{t+1}$ is the predicted continuous future state, $\hat{y}_{t+1} \in \{0..12\}$ is the predicted attack class, $\hat{m}_{t+1} \in \{0..5\}$ is the predicted MITRE ATT&CK tactical stage, and $\hat{p}_{\text{order}}$ is the sequence order discrimination signal.

```
RAW PACKET PCAP ──┐
                  ├─► [Dual Fusion] ──► [Recurrent GRU Core] ──► [K-Step Rollout] ──► [Mitigation Sandbox]
NETFLOW CSV ──────┘   (84-dim S_t)       (L=3 Context Window)     (t+1 to t+5)       (What-If Defense)
```

---

## 2. Dual Telemetry Ingestion & Standardized State Representation

NetGuard fuses dual-level network telemetry into a standardized 84-dimensional physical state vector:
1. **Flow-Level Telemetry (77 features):** Microsecond flow duration, forward/backward segment lengths, inter-arrival time (IAT) statistics (mean, std, max, min), TCP header flags (SYN, ACK, RST, FIN, PSH, URG), and bulk throughput metrics.
2. **Packet-Level PCAP Telemetry (7 features):** IP Time-to-Live variance (`ttl_variance`), mean TTL (`ttl_mean`), TCP advertised window dynamics (`swin_mean`, `swin_min`, `swin_max`), IP fragmentation flags, and TCP sequence backward jump retransmission counts.
3. **Temporal Standardization:** Continuous streaming sliding windows (10s step, $L=3$) z-score normalized against legitimate baseline statistics.

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

## 5. Verified Empirical Benchmarks & Sovereign Air-Gap Deployment

```
+--------------------------------------------------------------------------------------------------+
| Metric                      | Baseline (Logistic Reg) | NetGuard World Model | Performance Gain  |
|-----------------------------|-------------------------|----------------------|-------------------|
| Multi-Class Macro F1 (Raw)  | 0.0652                  | 0.2926               | +0.2274 (4.5x)    |
| Balanced Accuracy           | 50.12%                  | 79.15%               | +29.03% absolute  |
| Classification Accuracy     | 81.35%                  | 89.50%               | +8.15% absolute   |
| Threat ROC-AUC              | 0.5764                  | 0.9798               | +0.4034 area gain |
| Weighted F1-Score           | 0.8402                  | 0.9377               | +0.0975 gain      |
| K-Step Rollout Latency (CPU)| < 1000 ms (Target)      | 15.21 ms             | ~65x faster       |
| Temporal Shuffle Sensitivity| 0.00 sigma              | +3.28 sigma          | PASS (p < 0.001)  |
+--------------------------------------------------------------------------------------------------+
```

### Sovereign Air-Gap Compliance (Constraint C4)
NetGuard is self-contained: all model checkpoints, local feature extractors, SQLite/Parquet stores, FastAPI REST endpoints, and React 18 frontend run completely offline with zero external network connectivity.
