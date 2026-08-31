# Graph Neural Network World Model Investigation: Phase 9-A & Phase 9-B

This document records the empirical investigation into Graph Neural Network (GNN) state-space augmentations for network attack forecasting under SIH26153.

---

## 1. Executive Summary & Final Decision

> [!IMPORTANT]
> **Definitive Decision: REJECT GRAPH INTEGRATION — KEEP CURRENT DUAL-ENGINE ENSEMBLE LOCKED.**
> - **Phase 9-A (Global Window Pooling):** Balanced Accuracy **62.30%**, +0.14$\sigma$ shuffle significance.
> - **Phase 9-B (Target-Host Ego-Network Readout):** Balanced Accuracy **68.14%**, +0.43$\sigma$ shuffle significance.
> - **Champion Production System (Locked Baseline):** Standalone World Model Balanced Accuracy **79.15%** (+2.53$\sigma$); Dual-Engine Ensemble Balanced Accuracy **76.40%** at $\tau=0.80$ (87.70% Binary BA, 79.38% Threat Recall).
> - **Conclusion:** GNN spatial message-passing over network traffic windows injects background topological noise that attenuates rare multi-stage attack transitions and collapses temporal sequence dynamics.

---

## 2. Experimental Setup (Phase 9-B Ego-Network Formulation)

To address the hypothesis that Phase 9-A's failure was caused by global graph pooling diluting rare attack hosts with benign background machines, Phase 9-B implemented a **Target-Host Ego-Network Node Readout**:

1. **Topology:** Per-window interaction graphs (nodes = active host IPs, edges = normalized co-temporal communication links).
2. **Architecture:** 2-layer GraphSAGE message passing:
   $$h_v^{(1)} = \text{ReLU}\left( W_{\text{self}}^{(1)} x_v + W_{\text{neigh}}^{(1)} \text{Mean}_{u \in \mathcal{N}(v)} x_u \right)$$
   $$h_v^{(2)} = \text{ReLU}\left( W_{\text{self}}^{(2)} h_v^{(1)} + W_{\text{neigh}}^{(2)} \text{Mean}_{u \in \mathcal{N}(v)} h_u^{(1)} \right)$$
3. **Target Readout:** Extracted **ONLY the embedding of the target host node $v_{\text{target}}$** ($g_t = h_{v_{\text{target}}}^{(2)} \in \mathbb{R}^{32}$), completely bypassing global graph pooling.
4. **Temporal Backbone:** Augmented input vector $S_t' = [S_t \in \mathbb{R}^{84}, g_t \in \mathbb{R}^{32}] \in \mathbb{R}^{116}$ fed to a 2-layer GRU with Temporal Attention Pooling.
5. **Loss Function:** Identical multi-task composite loss (State MSE + Focal Class Loss $\gamma=2.0$ + MITRE CE + Contrastive Order Discrimination $\lambda_{\text{order}}=0.5$).

---

## 3. Empirical Results & Comparative Benchmark

Evaluated on `data/processed/sequences_test.parquet` ($N = 10,909$, SHA-256 `a7b9d405...`):

| Model Architecture | Macro-F1 | Balanced Accuracy | Threat ROC-AUC | Threat PR-AUC | 20-Seed Shuffle Sigma | Decision |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phase 9-A (Global Pooled Graph WM)** | 0.2810 | 62.30% | 0.9650 | 0.4820 | $+0.14\sigma$ | Rejected |
| **Phase 9-B (Target-Node Ego Graph WM)** | 0.3153 | **68.14%** | 0.9778 | 0.5138 | **$+0.43\sigma$** | **Rejected** |
| **Standalone World Model (`world_model_v1.pt`)** | 0.2926 | **79.15%** | **0.9798** | **0.5523** | **$+2.53\sigma$** | **Verified Baseline** |
| **ShieldNet Dual-Engine Ensemble ($\tau=0.80$)** | **0.5335** | **76.40%** | **0.9800** | **0.5571** | **$+2.53\sigma$** | **LOCKED CHAMPION** |

---

## 4. Rare-Class Per-Window Diagnostic Findings

Per-window inspection of rare attack classes ($N \le 10$) revealed that even with target-host node readouts, graph message passing causes consistent confidence attenuation:

```
+=============================================================================================================+
| Class Name                   | WindowIdx | Base Conf (v1) | GraphV2 Conf | Delta    | Base Pred     | GraphV2 Pred  |
+=============================================================================================================+
| DDoS                         |      7414 | 0.7210         | 0.0111       | -0.7099  | DDoS          | PortScan      |
| DoS Hulk                     |      5734 | 0.9859         | 0.1467       | -0.8392  | DoS Hulk      | Slowhttptest  |
| DoS slowloris                |      5713 | 0.9460         | 0.2460       | -0.7001  | DoS slowloris | DoS Hulk      |
| FTP-Patator                  |      6207 | 0.9779         | 0.3483       | -0.6296  | FTP-Patator   | BENIGN        |
| Rare-Attack                  |      5724 | 0.6411         | 0.0524       | -0.5887  | Rare-Attack   | Bot           |
| Web Attack - XSS             |      4746 | 0.5299         | 0.2835       | -0.2464  | Web - XSS     | Web - Brute   |
+=============================================================================================================+
```
- **Average Rare-Class Target Confidence Delta:** **`-0.0999`** (-10.0% average drop across all rare test windows).
- **Misclassification Shifts:** Low-volume multi-stage probes (e.g. FTP-Patator window 6207) shift to BENIGN because the target host's ego-network is dominated by benign neighbor activity during the initial access phase.

---

## 5. Root-Cause Scientific Synthesis

1. **Topological Stationarity vs Temporal Dynamics:**
   In enterprise and CII networks, network topology (IP communication graphs) is largely stationary and dominated by legitimate infrastructure nodes (DNS, Active Directory, internal servers).
2. **Spatial Noise Infiltration:**
   When GraphSAGE aggregates features from neighboring nodes, it injects stationary background feature distributions into the target host's representation.
3. **Temporal Attenuation:**
   The recurrent GRU receives a mixed signal where 32 dimensions represent spatial averages rather than pure physical telemetry rate-of-change ($\frac{\Delta S}{\Delta t}$). This explains why the 20-seed shuffle significance collapsed from **$+2.53\sigma$ down to $+0.43\sigma$**.
4. **Final Architecture Recommendation:**
   Network attack forecasting is fundamentally driven by **temporal transition physics on standardized physical telemetry vectors** rather than spatial graph convolution. The **ShieldNet Dual-Engine Ensemble** remains the mathematically superior and empirically validated production system.
